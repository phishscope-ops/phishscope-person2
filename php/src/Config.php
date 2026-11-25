<?php
declare(strict_types=1);
namespace P2;

/** All settings come from environment variables. Every one has a safe default, so the service runs with nothing set. */
final class Config
{
    public string $engineUrlBase = '';
    public string $engineApiKey = '';
    public float $engineTimeout = 3.0;
    public string $vtApiKey = '';
    public string $blocklistFile = '';
    public float $intelTimeout = 4.0;
    public int $intelCacheSeconds = 3600;
    public float $fetchTimeout = 4.0;
    public float $fetchTotalDeadline = 10.0;
    public int $maxRedirects = 5;
    public int $maxResponseBytes = 65536;
    public array $allowedPorts = [80, 443, 8080, 8443];
    public int $maxUrlLen = 2048;
    public int $maxSmsLen = 2000;
    public int $maxEmailBytes = 5000000;
    public int $maxLinksPerItem = 10;
    public float $protectionDeadline = 6.0;
    public float $browserDeadline = 12.0;
    public string $apiKey = '';
    public int $rateLimitPerMinute = 120;
    public string $dbPath = '';
    public int $scanTtlSeconds = 604800;

    public static function fromEnv(): self
    {
        $c = new self();
        $s = fn(string $n, string $d = ''): string => (string)(getenv($n) !== false ? getenv($n) : $d);
        $f = fn(string $n, float $d): float => is_numeric(getenv($n)) ? (float)getenv($n) : $d;
        $i = fn(string $n, int $d): int => is_numeric(getenv($n)) ? (int)getenv($n) : $d;
        $c->engineUrlBase = rtrim($s('P2_ENGINE_URL_BASE'), '/');
        $c->engineApiKey = $s('P2_ENGINE_API_KEY');
        $c->engineTimeout = $f('P2_ENGINE_TIMEOUT', 3.0);
        $c->vtApiKey = $s('VT_API_KEY');
        $c->blocklistFile = $s('P2_BLOCKLIST_FILE');
        $c->intelTimeout = $f('P2_INTEL_TIMEOUT', 4.0);
        $c->intelCacheSeconds = $i('P2_INTEL_CACHE_SECONDS', 3600);
        $c->fetchTimeout = $f('P2_FETCH_TIMEOUT', 4.0);
        $c->fetchTotalDeadline = $f('P2_FETCH_DEADLINE', 10.0);
        $c->maxRedirects = $i('P2_MAX_REDIRECTS', 5);
        $c->maxResponseBytes = $i('P2_MAX_RESPONSE_BYTES', 65536);
        $c->maxUrlLen = $i('P2_MAX_URL_LEN', 2048);
        $c->maxSmsLen = $i('P2_MAX_SMS_LEN', 2000);
        $c->maxEmailBytes = $i('P2_MAX_EMAIL_BYTES', 5000000);
        $c->maxLinksPerItem = $i('P2_MAX_LINKS', 10);
        $c->protectionDeadline = $f('P2_PROTECTION_DEADLINE', 6.0);
        $c->browserDeadline = $f('P2_BROWSER_DEADLINE', 12.0);
        $c->apiKey = $s('P2_API_KEY');
        $c->rateLimitPerMinute = $i('P2_RATE_LIMIT', 120);
        $c->dbPath = $s('P2_DB_PATH', sys_get_temp_dir() . '/p2_scans.sqlite3');
        $c->scanTtlSeconds = $i('P2_SCAN_TTL', 604800);
        return $c;
    }
}
