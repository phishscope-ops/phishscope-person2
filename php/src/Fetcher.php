<?php
declare(strict_types=1);
namespace P2;

class FetchError extends \Exception
{
    public string $code2;
    public function __construct(string $code2) { parent::__construct($code2); $this->code2 = $code2; }
}

final class Hop
{
    public ?int $status = null;
    public ?string $ip = null;
    public int $ms = 0;
    public string $note = '';
    public function __construct(public string $url) {}
}

final class Trace
{
    /** @var Hop[] */
    public array $hops = [];
    public string $finalUrl = '';
    public bool $complete = false;       // true only when we reached a final non-redirect answer
    public string $blockedReason = '';   // set when SSRF protection refused a hop
    public string $error = '';           // timeout, dns_failed, too_many_redirects, redirect_loop, tls_error, ...
    public bool $truncated = false;
    public string $contentType = '';

    public function __construct(public string $startUrl) { $this->finalUrl = $startUrl; }

    public function chain(): array { return array_map(fn(Hop $h) => $h->url, $this->hops); }
}

/**
 * Safe redirect tracer (Secure Browser 23, security 9, 10). No JavaScript is run and no page content is kept.
 * Redirects are followed by hand, every hop is re-checked, the connection is pinned to the vetted IP
 * (CURLOPT_RESOLVE keeps the real host name for the Host header and TLS), and time, hops and size are capped.
 */
class Fetcher
{
    const UA = 'Mozilla/5.0 (compatible; PhishScopeScanner/1.0; +link-check)';
    /** @var callable */
    private $resolver;
    /** @var callable */
    private $http;

    public function __construct(private Config $cfg, ?callable $resolver = null, ?callable $http = null)
    {
        $this->resolver = $resolver ?? [Ssrf::class, 'systemResolver'];
        $this->http = $http ?? [$this, 'curlRequest'];
    }

    public function trace(string $url, ?float $deadlineAt = null): Trace
    {
        $tr = new Trace($url);
        $deadline = microtime(true) + $this->cfg->fetchTotalDeadline;
        if ($deadlineAt !== null) $deadline = min($deadline, $deadlineAt);
        $current = $url;
        $seen = [];
        for ($i = 0; $i < $this->cfg->maxRedirects + 1; $i++) {
            if (microtime(true) > $deadline) { $tr->error = 'timeout'; return $tr; }
            try {
                $current = U::normalize($current, $this->cfg->maxUrlLen);
            } catch (BadUrl) {
                $tr->error = 'bad_redirect_target';
                return $tr;
            }
            if (isset($seen[$current])) { $tr->error = 'redirect_loop'; return $tr; }
            $seen[$current] = true;
            $host = U::hostOf($current);
            $port = U::portOf($current);
            $hop = new Hop($current);
            $tr->hops[] = $hop;
            $tr->finalUrl = $current;
            try {  // the destination check runs on EVERY hop, including the first
                $ips = Ssrf::checkDestination($host, $port, $this->cfg->allowedPorts, $this->resolver);
            } catch (SsrfBlocked $e) {
                $hop->note = 'blocked:' . $e->reason;
                $tr->blockedReason = $e->reason;
                return $tr;
            }
            $hop->ip = $ips[0];
            $t0 = microtime(true);
            try {
                $remaining = max(0.5, $deadline - microtime(true));
                [$status, $loc, $ct, $trunc] = ($this->http)($current, $host, $port, $ips[0], $remaining);
            } catch (FetchError $e) {
                $tr->error = $e->code2;
                return $tr;
            }
            $hop->ms = (int)((microtime(true) - $t0) * 1000);
            $hop->status = $status;
            $tr->contentType = (string)$ct;
            $tr->truncated = (bool)$trunc;
            if (in_array($status, [301, 302, 303, 307, 308], true) && $loc !== '') {
                $current = U::join($current, $loc);
                continue;
            }
            $tr->complete = true;
            return $tr;
        }
        $tr->error = 'too_many_redirects';
        return $tr;
    }

    /** @return array{0:int,1:string,2:string,3:bool} status, location, content-type, truncated */
    public function curlRequest(string $url, string $host, int $port, string $ip, float $remaining): array
    {
        $reqUrl = preg_replace('#^([a-z]+://)[^/?\#]*@#i', '$1', $url) ?? $url;  // never send userinfo
        $ch = curl_init($reqUrl);
        $status = 0; $loc = ''; $ct = ''; $total = 0; $trunc = false;
        $cap = $this->cfg->maxResponseBytes;
        $pin = $host . ':' . $port . ':' . (strpos($ip, ':') !== false ? "[$ip]" : $ip);
        curl_setopt_array($ch, [
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_RESOLVE => [$pin],
            CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
            CURLOPT_TIMEOUT_MS => (int)(min($remaining, $this->cfg->fetchTimeout * 2) * 1000),
            CURLOPT_CONNECTTIMEOUT_MS => (int)(min($remaining, $this->cfg->fetchTimeout) * 1000),
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_USERAGENT => self::UA,
            CURLOPT_HTTPHEADER => ['Accept: text/html,*/*;q=0.5'],
            CURLOPT_HEADERFUNCTION => function ($c, string $line) use (&$status, &$loc, &$ct) {
                if (preg_match('#^HTTP/\S+\s+(\d{3})#', $line, $m)) { $status = (int)$m[1]; $loc = ''; $ct = ''; }
                elseif (stripos($line, 'location:') === 0) $loc = trim(substr($line, 9));
                elseif (stripos($line, 'content-type:') === 0) $ct = trim(substr($line, 13));
                return strlen($line);
            },
            CURLOPT_WRITEFUNCTION => function ($c, string $data) use (&$total, &$trunc, $cap) {
                $total += strlen($data);
                if ($total >= $cap) { $trunc = true; return -1; }
                return strlen($data);
            },
        ]);
        curl_exec($ch);
        $errno = curl_errno($ch);
        $error = curl_error($ch);
        if ($status === 0) $status = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        if ($errno !== 0 && !($trunc && $errno === 23)) {
            if ($errno === 28) throw new FetchError('timeout');
            if (in_array($errno, [35, 51, 53, 54, 58, 59, 60, 64, 66, 77, 80, 82, 83, 90, 91], true)) throw new FetchError('tls_error');
            if (in_array($errno, [6, 7], true)) throw new FetchError('connect_error');
            if (in_array($errno, [1, 3], true)) throw new FetchError('bad_redirect_target');
            throw new FetchError('http_error');
        }
        if ($status === 0) throw new FetchError('http_error');
        return [$status, $loc, $ct, $trunc];
    }
}
