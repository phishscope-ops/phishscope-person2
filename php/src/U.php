<?php
declare(strict_types=1);
namespace P2;

class BadUrl extends \Exception {}

/** URL parsing, normalisation, defanging and link extraction (requirements 1, 2). */
final class U
{
    const CTRL = '/[\x00-\x20\x7f\x{200b}-\x{200f}\x{202a}-\x{202e}\x{2060}\x{feff}]/u';
    const FILE_EXT = ['txt','pdf','doc','docx','xls','xlsx','png','jpg','jpeg','gif','zip','exe','py','js','html','htm','css','json','md','csv','mp3','mp4','apk','php'];

    public static function utf8(string $s): string
    {
        return mb_check_encoding($s, 'UTF-8') ? $s : mb_convert_encoding($s, 'UTF-8', 'UTF-8');
    }

    public static function defang(string $v): string
    {
        $v = preg_replace('/^http/i', 'hxxp', $v) ?? $v;
        return str_replace('.', '[.]', $v);
    }

    public static function refang(string $v): string
    {
        $v = str_replace(['[.]', '(.)', '[:]'], ['.', '.', ':'], trim($v));
        return preg_replace('/^hxxp/i', 'http', $v) ?? $v;
    }

    /** inet_aton rules: 2130706433, 0x7f.1, 017700000001, 127.1 all work. */
    public static function inetAton(string $h): ?string
    {
        $parts = explode('.', $h);
        $n = count($parts);
        if ($n > 4) return null;
        $vals = [];
        foreach ($parts as $p) {
            if ($p === '') return null;
            if (preg_match('/^0[xX]([0-9a-fA-F]+)$/', $p, $m)) $v = hexdec($m[1]);
            elseif (preg_match('/^0[0-7]+$/', $p)) $v = octdec($p);
            elseif (preg_match('/^[0-9]+$/', $p)) $v = (int)$p;
            else return null;
            if (!is_int($v) && !is_float($v)) return null;
            $vals[] = (int)$v;
        }
        $total = 0;
        for ($k = 0; $k < $n - 1; $k++) {
            if ($vals[$k] > 255) return null;
            $total |= $vals[$k] << (8 * (3 - $k));
        }
        $last = $vals[$n - 1];
        $max = (1 << (8 * (4 - ($n - 1)))) - 1;
        if ($last > $max || $last < 0) return null;
        $total |= $last;
        return long2ip($total & 0xFFFFFFFF);
    }

    /** Normalised IP string for plain, decimal, hex, octal, short IPv4 and IPv6 forms, or null. */
    public static function parseIpLiteral(string $host): ?string
    {
        $h = trim($host, '[]');
        if ($h === '') return null;
        if (strpos($h, ':') !== false) {
            $b = @inet_pton($h);
            return $b === false ? null : (string)inet_ntop($b);
        }
        if (preg_match('/^[0-9a-fA-Fx.]+$/', $h) && preg_match('/\d/', $h)) {
            return self::inetAton($h);
        }
        return null;
    }

    public static function punycodeLabel(string $label): string
    {
        if (preg_match('/^[\x00-\x7f]*$/', $label)) return strtolower($label);
        $label = mb_strtolower($label, 'UTF-8');
        $cps = [];
        foreach (preg_split('//u', $label, -1, PREG_SPLIT_NO_EMPTY) ?: [] as $ch) $cps[] = mb_ord($ch, 'UTF-8');
        $out = '';
        foreach ($cps as $c) if ($c < 128) $out .= chr($c);
        $b = strlen($out);
        $h = $b;
        if ($b > 0) $out .= '-';
        $n = 128; $delta = 0; $bias = 72;
        $adapt = function (int $delta, int $num, bool $first) {
            $delta = $first ? intdiv($delta, 700) : $delta >> 1;
            $delta += intdiv($delta, $num);
            $k = 0;
            while ($delta > 455) { $delta = intdiv($delta, 35); $k += 36; }
            return $k + intdiv(36 * $delta, $delta + 38);
        };
        $digit = fn(int $d) => chr($d < 26 ? $d + 97 : $d + 22);
        $len = count($cps);
        while ($h < $len) {
            $m = PHP_INT_MAX;
            foreach ($cps as $c) if ($c >= $n && $c < $m) $m = $c;
            $delta += ($m - $n) * ($h + 1);
            $n = $m;
            foreach ($cps as $c) {
                if ($c < $n) $delta++;
                if ($c === $n) {
                    $q = $delta;
                    for ($k = 36;; $k += 36) {
                        $t = $k <= $bias ? 1 : ($k >= $bias + 26 ? 26 : $k - $bias);
                        if ($q < $t) break;
                        $out .= $digit($t + (($q - $t) % (36 - $t)));
                        $q = intdiv($q - $t, 36 - $t);
                    }
                    $out .= $digit($q);
                    $bias = $adapt($delta, $h + 1, $h === $b);
                    $delta = 0;
                    $h++;
                }
            }
            $delta++; $n++;
        }
        return 'xn--' . $out;
    }

    public static function idna(string $host): string
    {
        if (function_exists('idn_to_ascii')) {
            $r = idn_to_ascii($host, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
            if ($r === false) throw new BadUrl('bad host name');
            return $r;
        }
        return implode('.', array_map([self::class, 'punycodeLabel'], explode('.', $host)));
    }

    public static function normalize(mixed $raw, int $maxLen = 2048): string
    {
        if (!is_string($raw)) throw new BadUrl('not text');
        $raw = self::refang(self::utf8($raw));
        if (mb_strlen($raw, 'UTF-8') > $maxLen) throw new BadUrl('url too long');
        $raw = preg_replace(self::CTRL, '', $raw) ?? '';
        if ($raw === '') throw new BadUrl('empty url');
        if (strpos($raw, '://') === false) {
            if (preg_match('/^[a-z][a-z0-9+.-]*:/i', $raw) && !preg_match('/^[^\/]+:\d+(\/|$)/', $raw)) {
                throw new BadUrl('scheme not allowed');
            }
            $raw = 'http://' . ltrim($raw, '/');
        }
        if (!preg_match('#^([A-Za-z][A-Za-z0-9+.-]*)://([^/?\#]*)([^?\#]*)(?:\?([^\#]*))?(?:\#.*)?$#s', $raw, $m)) {
            throw new BadUrl('malformed url');
        }
        $scheme = strtolower($m[1]);
        $netloc = $m[2];
        $path = $m[3];
        $query = $m[4] ?? '';
        if (!in_array($scheme, ['http', 'https'], true)) throw new BadUrl('scheme not allowed');
        $userinfo = '';
        $hostport = $netloc;
        $at = strrpos($netloc, '@');
        if ($at !== false) { $userinfo = substr($netloc, 0, $at); $hostport = substr($netloc, $at + 1); }
        $port = null;
        if (str_starts_with($hostport, '[')) {
            $end = strpos($hostport, ']');
            if ($end === false) throw new BadUrl('malformed url');
            $host = substr($hostport, 1, $end - 1);
            $rest = substr($hostport, $end + 1);
            if ($rest !== '') {
                if (!preg_match('/^:(\d*)$/', $rest, $pm)) throw new BadUrl('malformed url');
                $port = $pm[1] === '' ? null : (int)$pm[1];
            }
        } else {
            $colon = strrpos($hostport, ':');
            if ($colon !== false) {
                $host = substr($hostport, 0, $colon);
                $ps = substr($hostport, $colon + 1);
                if ($ps !== '' && !preg_match('/^\d+$/', $ps)) throw new BadUrl('malformed url');
                $port = $ps === '' ? null : (int)$ps;
            } else {
                $host = $hostport;
            }
        }
        if ($port !== null && ($port < 0 || $port > 65535)) throw new BadUrl('malformed url');
        $host = strtolower(rtrim(mb_strtolower($host, 'UTF-8'), '.'));
        if ($host === '') throw new BadUrl('no host');
        if (preg_match('/[\s<>"\'\\\\^`{|}]/u', $host)) throw new BadUrl('invalid characters in host');
        $ip = self::parseIpLiteral($host);
        if ($ip !== null) {
            $host = strpos($ip, ':') !== false ? "[$ip]" : $ip;
        } else {
            $host = self::idna($host);
            if (!preg_match('/^[a-z0-9_.-]+$/', $host) || strpos($host, '..') !== false || strlen($host) > 253) {
                throw new BadUrl('bad host name');
            }
        }
        $out = $host;
        if ($userinfo !== '') $out = $userinfo . '@' . $host;
        if ($port) $out .= ':' . $port;
        return $scheme . '://' . $out . ($path === '' ? '/' : $path) . ($query !== '' ? '?' . $query : '');
    }

    public static function hostOf(string $url): string
    {
        if (!preg_match('#^[a-z]+://([^/?\#]*)#i', $url, $m)) return '';
        $nl = $m[1];
        $at = strrpos($nl, '@');
        if ($at !== false) $nl = substr($nl, $at + 1);
        if (str_starts_with($nl, '[')) { $e = strpos($nl, ']'); return strtolower(substr($nl, 1, ($e === false ? strlen($nl) : $e) - 1)); }
        $c = strrpos($nl, ':');
        if ($c !== false) $nl = substr($nl, 0, $c);
        return strtolower($nl);
    }

    public static function portOf(string $url): int
    {
        if (preg_match('#^([a-z]+)://[^/?\#]*?(?::(\d+))?(?:[/?\#]|$)#i', $url, $m) && ($m[2] ?? '') !== '') return (int)$m[2];
        return strtolower(substr($url, 0, 5)) === 'https' ? 443 : 80;
    }

    public static function schemeOf(string $url): string
    {
        return preg_match('#^([a-z]+)://#i', $url, $m) ? strtolower($m[1]) : '';
    }

    public static function hasUserinfo(string $url): bool
    {
        return preg_match('#^[a-z]+://[^/?\#]*@#i', $url) === 1;
    }

    public static function pathOf(string $url): string
    {
        return preg_match('#^[a-z]+://[^/?\#]*([^?\#]*)#i', $url, $m) ? $m[1] : '';
    }

    /** Resolve a Location header against the current URL (RFC 3986, enough for redirects). */
    public static function join(string $base, string $ref): string
    {
        $ref = trim($ref);
        if (preg_match('#^[a-z][a-z0-9+.-]*:#i', $ref) && !preg_match('#^[^/]+:\d+(/|$)#', $ref)) return $ref;
        preg_match('#^([a-z]+)://([^/?\#]*)([^?\#]*)(\?[^\#]*)?#i', $base, $b);
        $scheme = $b[1] ?? 'http'; $auth = $b[2] ?? ''; $bpath = $b[3] ?? '/';
        if (str_starts_with($ref, '//')) return $scheme . ':' . $ref;
        if ($ref === '') return $base;
        if ($ref[0] === '#') return $base;
        if ($ref[0] === '?') return "$scheme://$auth$bpath$ref";
        if ($ref[0] === '/') $path = $ref;
        else $path = substr($bpath, 0, (int)strrpos($bpath, '/') + 1) . $ref;
        $qpos = strpos($path, '?');
        $q = '';
        if ($qpos !== false) { $q = substr($path, $qpos); $path = substr($path, 0, $qpos); }
        $hpos = strpos($q === '' ? $path : $q, '#');
        $segs = [];
        foreach (explode('/', $path) as $s) {
            if ($s === '..') array_pop($segs);
            elseif ($s !== '.') $segs[] = $s;
        }
        $path = implode('/', $segs);
        if ($path === '' || $path[0] !== '/') $path = '/' . $path;
        return "$scheme://$auth$path$q";
    }

    public static function extractUrls(string $text, int $limit = 10): array
    {
        $text = self::utf8(substr($text, 0, 100000));
        $text = preg_replace_callback('/\S{600,}/', fn($m) => substr($m[0], 0, 600), $text) ?? '';
        preg_match_all('/\b(?:https?:\/\/|hxxps?:\/\/|www\.)[^\s<>"\'\x{200b}]+/iu', $text, $e, PREG_OFFSET_CAPTURE);
        $explicit = $e[0];
        preg_match_all('/\b(?:[a-z0-9-]{1,63}\.){1,10}(?:xn--[a-z0-9-]{2,59}|[a-z]{2,24})(?![a-z0-9-])(?::\d+)?(?:[\/?#][^\s<>"\']*)?/i', $text, $bm, PREG_OFFSET_CAPTURE);
        $cands = [];
        foreach ($explicit as [$s, $o]) $cands[] = [$o, $o + strlen($s), $s];
        foreach ($bm[0] as [$s, $o]) {
            $end = $o + strlen($s);
            $overlap = false;
            foreach ($explicit as [$es, $eo]) if ($o < $eo + strlen($es) && $end > $eo) { $overlap = true; break; }
            if ($overlap) continue;
            $before = $o > 0 ? $text[$o - 1] : '';
            $after = $end < strlen($text) ? $text[$end] : '';
            if ($before === '@' || $after === '@') continue;
            $cands[] = [$o, $end, $s];
        }
        usort($cands, fn($a, $b) => $a[0] <=> $b[0]);
        $out = [];
        $seen = [];
        foreach ($cands as [, , $raw]) {
            $cand = preg_replace('/[.,);\]}،؛؟!"\'>]+$/u', '', $raw) ?? $raw;
            try { $n = self::normalize($cand); } catch (BadUrl) { continue; }
            $host = self::hostOf($n);
            if (!preg_match('#^(https?|hxxps?)://#i', $cand) && !str_starts_with(strtolower($cand), 'www.')) {
                $tld = substr($host, (int)strrpos($host, '.') + (strpos($host, '.') === false ? 0 : 1));
                if (self::parseIpLiteral($host) === null && (ctype_digit($tld) || in_array($tld, self::FILE_EXT, true))) continue;
            }
            if (!isset($seen[$n])) { $seen[$n] = true; $out[] = $n; }
            if (count($out) >= $limit) break;
        }
        return $out;
    }
}
