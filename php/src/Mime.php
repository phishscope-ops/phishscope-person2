<?php
declare(strict_types=1);
namespace P2;

/** Small, defensive MIME reader (no extensions needed). Depth and part counts are capped so hostile mail cannot exhaust memory. */
final class Mime
{
    const MAX_DEPTH = 20;
    const MAX_PARTS = 200;

    /** @return array{headers:array,type:string,params:array,disposition:string,filename:string,body:string,parts:array} */
    public static function parse(string $raw, int $depth = 0, int &$count = 0): array
    {
        $count++;
        $raw = str_replace("\r\n", "\n", $raw);
        $pos = strpos($raw, "\n\n");
        if (str_starts_with($raw, "\n")) { $head = ''; $body = substr($raw, 1); }
        elseif ($pos === false) { $head = $raw; $body = ''; }
        else { $head = substr($raw, 0, $pos); $body = substr($raw, $pos + 2); }
        $headers = self::headers($head);
        [$type, $params] = self::structured($headers['content-type'][0] ?? 'text/plain');
        [$disp, $dparams] = self::structured($headers['content-disposition'][0] ?? '');
        $filename = self::paramValue($dparams, 'filename') ?? self::paramValue($params, 'name') ?? '';
        $node = ['headers' => $headers, 'type' => $type ?: 'text/plain', 'params' => $params, 'disposition' => $disp, 'filename' => $filename, 'body' => '', 'parts' => []];
        if (str_starts_with($node['type'], 'multipart/') && isset($params['boundary']) && $depth < self::MAX_DEPTH) {
            $b = '--' . $params['boundary'];
            foreach (explode("\n", $body) as $_) { break; }
            $chunks = preg_split('/^' . preg_quote($b, '/') . '(?:--)?[ \t]*$/m', $body) ?: [];
            array_shift($chunks);
            foreach ($chunks as $c) {
                if ($count >= self::MAX_PARTS) break;
                $c = ltrim($c, "\n");
                if (trim($c) === '') continue;
                $node['parts'][] = self::parse($c, $depth + 1, $count);
            }
        } else {
            $node['body'] = self::decode($body, strtolower(trim($headers['content-transfer-encoding'][0] ?? '')));
            $cs = $params['charset'] ?? 'utf-8';
            if (str_starts_with($node['type'], 'text/')) $node['body'] = self::toUtf8($node['body'], $cs);
        }
        return $node;
    }

    public static function headers(string $head): array
    {
        $head = preg_replace("/\n[ \t]+/", ' ', $head) ?? '';
        $out = [];
        foreach (explode("\n", $head) as $line) {
            if (!preg_match('/^([A-Za-z0-9-]+):\s*(.*)$/', $line, $m)) continue;
            $out[strtolower($m[1])][] = self::mimeWords($m[2]);
        }
        return $out;
    }

    public static function mimeWords(string $v): string
    {
        if (strpos($v, '=?') === false) return $v;
        $d = @iconv_mime_decode($v, ICONV_MIME_DECODE_CONTINUE_ON_ERROR, 'UTF-8');
        return $d === false ? $v : $d;
    }

    /** @return array{0:string,1:array} */
    public static function structured(string $v): array
    {
        $parts = preg_split('/;(?=(?:[^"]*"[^"]*")*[^"]*$)/', $v) ?: [''];
        $main = strtolower(trim(array_shift($parts)));
        $params = [];
        foreach ($parts as $p) {
            if (!preg_match('/^\s*([\w*.-]+)\s*=\s*(.*?)\s*$/s', $p, $m)) continue;
            $val = $m[2];
            if (strlen($val) >= 2 && $val[0] === '"') $val = stripslashes(substr($val, 1, strrpos($val, '"') ? strrpos($val, '"') - 1 : null));
            $params[strtolower($m[1])] = $val;
        }
        return [$main, $params];
    }

    private static function paramValue(array $params, string $name): ?string
    {
        if (isset($params[$name])) return self::mimeWords($params[$name]);
        if (isset($params[$name . '*'])) {
            if (preg_match("/^([\w-]*)'[\w-]*'(.*)$/", $params[$name . '*'], $m)) return self::toUtf8(rawurldecode($m[2]), $m[1] ?: 'utf-8');
            return $params[$name . '*'];
        }
        return null;
    }

    public static function decode(string $body, string $cte): string
    {
        return match ($cte) {
            'base64' => (string)base64_decode($body, false),
            'quoted-printable' => quoted_printable_decode($body),
            default => $body,
        };
    }

    public static function toUtf8(string $s, string $charset): string
    {
        $cs = strtoupper(trim($charset)) ?: 'UTF-8';
        if ($cs === 'UTF-8' || $cs === 'US-ASCII') return U::utf8($s);
        try {
            $r = @mb_convert_encoding($s, 'UTF-8', $cs);
            return is_string($r) ? U::utf8($r) : U::utf8($s);
        } catch (\Throwable) {
            return U::utf8($s);
        }
    }

    /** Flat list of leaf parts. */
    public static function leaves(array $node): array
    {
        if (!$node['parts']) return [$node];
        $out = [];
        foreach ($node['parts'] as $p) foreach (self::leaves($p) as $l) $out[] = $l;
        return $out;
    }
}
