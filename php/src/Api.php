<?php
declare(strict_types=1);
namespace P2;

/**
 * HTTP contract, framework free. handle() takes the request parts and returns [status, body array], so the same
 * code runs under Apache, nginx+FPM, `php -S`, and in tests.
 * PHP runs one request at a time per worker, so scans run inside the request: the POST answers 202 with the finished
 * result already stored, and GET /v1/scans/{id} returns it. Clients written for polling work unchanged.
 */
final class Api
{
    const VERSION = '1.0.0-php';

    public function __construct(private Config $cfg, private Scanner $scanner, private Store $store) {}

    /** @param array<string,string> $headers lowercase names */
    public function handle(string $method, string $path, array $headers, string $body, string $clientIp = 'anon'): array
    {
        try {
            return $this->route(strtoupper($method), rtrim($path, '/') ?: '/', $headers, $body, $clientIp);
        } catch (\Throwable $e) {
            LogSafe::error('unhandled ' . get_class($e));
            return [500, ['error' => 'internal_error']];
        }
    }

    private function route(string $m, string $p, array $h, string $raw, string $ip): array
    {
        if ($m === 'GET' && $p === '/health') {
            return [200, ['status' => 'ok', 'version' => self::VERSION, 'engine' => $this->cfg->engineUrlBase !== '' ? 'remote' : 'local-heuristics',
                'threat_intel' => ['virustotal' => $this->cfg->vtApiKey !== '', 'local_blocklist' => $this->cfg->blocklistFile !== '']]];
        }
        $known = ['POST' => ['/v1/urls/scan', '/v1/emails/scan', '/v1/sms/scan', '/v1/protection/sms', '/v1/browser/precheck']];
        $isScanGet = $m === 'GET' && preg_match('#^/v1/scans/([^/]+)$#', $p, $sm);
        if (!($isScanGet || ($m === 'POST' && in_array($p, $known['POST'], true)))) {
            return [404, ['error' => 'not_found']];
        }
        if ($this->cfg->apiKey !== '') {
            $given = $h['x-api-key'] ?? '';
            if (!hash_equals($this->cfg->apiKey, $given)) return [401, ['error' => 'unauthorized']];
        }
        $client = ($h['x-api-key'] ?? '') !== '' ? $h['x-api-key'] : $ip;
        if (!$this->store->allow($client, $this->cfg->rateLimitPerMinute)) return [429, ['error' => 'rate_limited']];

        if ($isScanGet) {
            $rec = $this->store->get($sm[1]);
            return $rec ? [200, $rec] : [404, ['error' => 'scan_not_found']];
        }
        $in = json_decode($raw, true);
        if (!is_array($in) || array_is_list($in) && $in !== []) return [422, ['error' => 'invalid_json_body']];
        $ref = $this->str($in, 'client_ref', 0, 80, false);
        if ($ref === false) return [422, ['error' => 'invalid_client_ref']];

        switch ($p) {
            case '/v1/urls/scan':
                $url = $this->str($in, 'url', 1, 4096, true);
                if ($url === false) return [422, ['error' => 'invalid_url']];
                return $this->job('url', $ref, fn() => $this->scanner->scanUrl($url));
            case '/v1/sms/scan':
                $b = $this->str($in, 'body', 1, 20000, true);
                $s = $this->str($in, 'sender', 0, 64, false);
                if ($b === false || $s === false) return [422, ['error' => 'invalid_sms']];
                return $this->job('sms', $ref, fn() => $this->scanner->scanSms($b, (string)$s));
            case '/v1/emails/scan':
                $rawMail = null;
                if (!empty($in['eml_base64']) && is_string($in['eml_base64'])) {
                    $rawMail = base64_decode($in['eml_base64'], true);
                    if ($rawMail === false) return [422, ['error' => 'invalid_base64']];
                } elseif (!empty($in['eml_text']) && is_string($in['eml_text'])) {
                    $rawMail = $in['eml_text'];
                } else {
                    return [422, ['error' => 'eml_base64_or_eml_text_required']];
                }
                if (strlen($rawMail) > $this->cfg->maxEmailBytes) return [413, ['error' => 'email_too_large', 'max_bytes' => $this->cfg->maxEmailBytes]];
                return $this->job('email', $ref, fn() => $this->scanner->scanEmail($rawMail));
            case '/v1/protection/sms':
                $b = $this->str($in, 'body', 1, 20000, true);
                $s = $this->str($in, 'sender', 0, 64, false);
                $mid = $this->str($in, 'message_id', 0, 80, false);
                if ($b === false || $s === false || $mid === false) return [422, ['error' => 'invalid_sms']];
                return $this->protect($b, (string)$s, $mid);
            case '/v1/browser/precheck':
                $url = $this->str($in, 'url', 1, 4096, true);
                if ($url === false) return [422, ['error' => 'invalid_url']];
                try {
                    return [200, Enrich::apply($this->scanner->browserPrecheck($url), $ref)];
                } catch (\Throwable) {
                    return [200, Enrich::apply($this->unknownResult('الفحص أخد وقت أطول من المسموح', ['browser' => ['open_allowed' => false, 'interstitial' => 'unverified_notice', 'title' => 'ما قدرناش نتأكد من الموقع', 'user_can_proceed' => true]]), $ref)];
                }
        }
        return [404, ['error' => 'not_found']];
    }

    /** @return string|null|false string when valid, null when absent and optional, false when invalid */
    private function str(array $in, string $key, int $min, int $max, bool $required): string|null|false
    {
        if (!array_key_exists($key, $in) || $in[$key] === null) return $required ? false : null;
        if (!is_string($in[$key])) return false;
        $n = mb_strlen($in[$key]);
        return ($n < $min || $n > $max) ? false : $in[$key];
    }

    private function unknownResult(string $why, array $extra = []): array
    {
        return array_merge(['verdict' => 'unknown', 'risk_score' => 0, 'action' => Verdict::ACTIONS['unknown'], 'confidence' => 'limited', 'links' => [],
            'reasons' => [$why], 'caveats' => ['اعتبر النتيجة غير مؤكدة'], 'evidence' => []], $extra);
    }

    private function job(string $kind, ?string $ref, callable $fn): array
    {
        $id = $this->store->create($kind);
        $this->store->update($id, 'running');
        try {
            $this->scanner->deadlineAt = microtime(true) + $this->cfg->fetchTotalDeadline * 3 + 30;
            $res = Enrich::apply($fn(), $ref);
            $this->store->update($id, 'completed', $res);
        } catch (\Throwable $e) {
            LogSafe::error('job failed ' . get_class($e));
            $this->store->update($id, 'failed', Enrich::apply($this->unknownResult('فشل التحليل', ['caveats' => ['حاول تاني بعد شوية']]), $ref));
        } finally {
            $this->scanner->deadlineAt = null;
        }
        return [202, ['scan_id' => $id, 'status' => 'completed', 'poll_url' => "/v1/scans/$id", 'result' => $this->store->get($id)['result']]];
    }

    private function protect(string $body, string $sender, ?string $mid): array
    {
        $t0 = microtime(true);
        $this->scanner->deadlineAt = $t0 + $this->cfg->protectionDeadline;
        try {
            $res = $this->scanner->scanSms($body, $sender);
            $status = 'ok';
            if (microtime(true) - $t0 > $this->cfg->protectionDeadline) {
                $res = $this->unknownResult('التحليل أخد وقت أطول من المسموح');
                $status = 'timeout';
            }
        } catch (\Throwable $e) {
            LogSafe::error('protection failed ' . get_class($e));
            $res = $this->unknownResult('الخدمة مش متاحة حالياً');
            $status = 'service_unavailable';
        } finally {
            $this->scanner->deadlineAt = null;
        }
        $res = Enrich::apply($res, $mid);
        return [200, array_merge(['message_id' => $mid, 'status' => $status, 'show_warning' => $res['verdict'] !== 'safe'], $res)];
    }
}
