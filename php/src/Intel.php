<?php
declare(strict_types=1);
namespace P2;

/** One threat-intel answer. verdict is malicious, suspicious or null. Never 'safe'. */
final class IntelResult
{
    public function __construct(public string $provider, public string $state, public ?string $verdict = null,
                                public string $detail = '', public array $stats = []) {}

    public function toArray(): array
    {
        return ['provider' => $this->provider, 'state' => $this->state, 'verdict' => $this->verdict, 'detail' => $this->detail, 'stats' => $this->stats];
    }
}

/** Threat Intelligence (25 to 28). Providers are optional and free. A missing, failed or empty answer is never "safe". */
final class Intel
{
    public static function registeredDomain(string $host): string
    {
        $parts = explode('.', $host);
        if (count($parts) <= 2) return $host;
        $last2 = implode('.', array_slice($parts, -2));
        if (in_array($last2, ['com.eg', 'gov.eg', 'edu.eg', 'org.eg', 'net.eg', 'co.uk', 'org.uk', 'com.sa', 'com.au', 'co.in'], true)) {
            return implode('.', array_slice($parts, -3));
        }
        return $last2;
    }
}

final class LocalBlocklist
{
    public string $name = 'local_blocklist';
    private array $domains = [];
    private array $urls = [];
    public bool $enabled = false;

    public function __construct(string $path)
    {
        if ($path !== '' && is_readable($path)) {
            foreach (file($path, FILE_IGNORE_NEW_LINES) ?: [] as $line) {
                $line = strtolower(trim($line));
                if ($line === '' || $line[0] === '#') continue;
                if (strpos($line, '/') !== false) $this->urls[rtrim($line, '/')] = true; else $this->domains[$line] = true;
            }
        }
        $this->enabled = $this->domains || $this->urls;
    }

    public function check(string $url): IntelResult
    {
        if (!$this->enabled) return new IntelResult($this->name, 'unavailable', null, 'no_blocklist_configured');
        $host = U::hostOf($url);
        if (isset($this->urls[rtrim(strtolower($url), '/')]) || isset($this->domains[$host]) || isset($this->domains[Intel::registeredDomain($host)])) {
            return new IntelResult($this->name, 'confirmed', 'malicious', 'listed_in_local_blocklist');
        }
        return new IntelResult($this->name, 'inconclusive', null, 'not_listed');
    }
}

final class VirusTotal
{
    public string $name = 'virustotal';
    private array $cache = [];
    /** @var callable */
    private $http;

    /** $http(url, headers, timeoutSeconds): array{0:int,1:string}. Replaceable for tests. */
    public function __construct(private Config $cfg, ?callable $http = null)
    {
        $this->http = $http ?? [Http::class, 'get'];
    }

    public function check(string $url): IntelResult
    {
        if ($this->cfg->vtApiKey === '') return new IntelResult($this->name, 'unavailable', null, 'no_api_key');
        $hit = $this->cache[$url] ?? null;
        if ($hit && $hit[0] > time()) return $hit[1];
        $uid = rtrim(strtr(base64_encode($url), '+/', '-_'), '=');
        try {
            [$code, $body] = ($this->http)("https://www.virustotal.com/api/v3/urls/$uid", ['x-apikey: ' . $this->cfg->vtApiKey], $this->cfg->intelTimeout);
        } catch (\Throwable) {
            return new IntelResult($this->name, 'unavailable', null, 'request_failed');
        }
        if ($code === 404) {
            $res = new IntelResult($this->name, 'inconclusive', null, 'url_not_known_to_provider');
        } elseif ($code === 429) {
            return new IntelResult($this->name, 'unavailable', null, 'quota_exceeded');
        } elseif ($code !== 200) {
            return new IntelResult($this->name, 'unavailable', null, "http_$code");
        } else {
            $j = json_decode($body, true);
            $stats = $j['data']['attributes']['last_analysis_stats'] ?? null;
            if (!is_array($stats)) return new IntelResult($this->name, 'unavailable', null, 'bad_response');
            $mal = (int)($stats['malicious'] ?? 0);
            $sus = (int)($stats['suspicious'] ?? 0);
            if ($mal >= 2) $res = new IntelResult($this->name, 'confirmed', 'malicious', "{$mal}_engines_flag_malicious", $stats);
            elseif ($mal === 1 || $sus >= 1) $res = new IntelResult($this->name, 'confirmed', 'suspicious', 'some_engines_flag_it', $stats);
            else $res = new IntelResult($this->name, 'inconclusive', null, 'no_detections_not_a_safety_proof', $stats);  // 0 detections is not a safety proof
        }
        $this->cache[$url] = [time() + $this->cfg->intelCacheSeconds, $res];
        return $res;
    }
}

final class IntelHub
{
    public array $providers;

    public function __construct(private Config $cfg, ?array $providers = null)
    {
        $this->providers = $providers ?? [new LocalBlocklist($cfg->blocklistFile), new VirusTotal($cfg)];
    }

    /** Checks every URL in the redirect chain: a bad middle hop matters even if the landing page looks clean. */
    public function lookup(array $urls): array
    {
        $out = [];
        foreach ($urls as $u) {
            foreach ($this->providers as $p) {
                try {
                    $r = $p->check($u);
                } catch (\Throwable) {
                    $r = new IntelResult($p->name ?? 'provider', 'unavailable', null, 'provider_error');
                }
                $r->stats = array_merge($r->stats, ['url_host' => U::hostOf($u)]);
                $out[] = $r;
            }
        }
        return $out;
    }
}

/** Tiny curl helpers, kept in one place so tests can replace them. */
final class Http
{
    public static function get(string $url, array $headers, float $timeout): array
    {
        $ch = curl_init($url);
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_HTTPHEADER => $headers, CURLOPT_TIMEOUT_MS => (int)($timeout * 1000),
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS, CURLOPT_FOLLOWLOCATION => false]);
        $body = curl_exec($ch);
        if ($body === false) throw new \RuntimeException('http_failed');
        return [(int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE), (string)$body];
    }

    public static function postJson(string $url, string $json, array $headers, float $timeout): array
    {
        $ch = curl_init($url);
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_POST => true, CURLOPT_POSTFIELDS => $json,
            CURLOPT_HTTPHEADER => array_merge(['Content-Type: application/json'], $headers), CURLOPT_TIMEOUT_MS => (int)($timeout * 1000),
            CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS, CURLOPT_FOLLOWLOCATION => false]);
        $body = curl_exec($ch);
        if ($body === false) throw new \RuntimeException('http_failed');
        return [(int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE), (string)$body];
    }
}
