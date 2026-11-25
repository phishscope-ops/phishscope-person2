<?php
declare(strict_types=1);
namespace P2;

/** Sensitive data must not reach logs (security 11). Message bodies and query strings are never logged, and a filter masks keys, tokens, emails and phones. */
final class LogSafe
{
    const PATTERNS = [
        ['/\b(bearer)\s+[A-Za-z0-9._~+\/=-]{8,}/i', '$1 ***'],
        ['/(x-apikey|authorization|api[_-]?key|token|secret|password|passwd|bearer)(\s*[:=]\s*|\s+)([^\s,;&"\']+)/i', '$1$2***'],
        ['/[\w.+-]+@[\w-]+\.[\w.-]+/', '***@***'],
        ['/(?<!\d)\+?\d[\d\s-]{8,16}\d(?!\d)/', '***phone***'],
        ['/\b[A-Fa-f0-9]{32,}\b/', '***hash***'],
        ['/\b[A-Za-z0-9_-]{32,}\b/', '***key***'],
        ['/(\?[^\s"\']*)/', '?***'],
    ];
    /** @var string[] lines captured when $capture is true (for tests) */
    public static array $captured = [];
    public static bool $capture = false;

    public static function scrub(string $text): string
    {
        foreach (self::PATTERNS as [$p, $r]) $text = preg_replace($p, $r, $text) ?? '';
        return $text;
    }

    public static function error(string $msg): void
    {
        $line = self::scrub($msg);
        if (self::$capture) self::$captured[] = $line; else error_log('[p2] ' . $line);
    }
}
