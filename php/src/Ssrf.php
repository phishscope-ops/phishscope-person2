<?php
declare(strict_types=1);
namespace P2;

class SsrfBlocked extends \Exception
{
    public string $reason;
    public function __construct(string $reason) { parent::__construct($reason); $this->reason = $reason; }
}

/** SSRF protection (security 8, 9, 10). Every outbound address is checked, including after each redirect. */
final class Ssrf
{
    const V4_BLOCKED = ['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24',
        '192.0.2.0/24', '192.88.99.0/24', '192.168.0.0/16', '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4'];
    const V6_BLOCKED = ['2001::/23', '2001:db8::/32', '3fff::/20', '2002::/16'];

    public static function inNet(string $bin, string $cidr): bool
    {
        [$net, $bits] = explode('/', $cidr);
        $nb = inet_pton($net);
        if ($nb === false || strlen($nb) !== strlen($bin)) return false;
        $bits = (int)$bits;
        $full = intdiv($bits, 8);
        if ($full && substr($bin, 0, $full) !== substr($nb, 0, $full)) return false;
        $rem = $bits % 8;
        if ($rem) {
            $mask = (0xFF << (8 - $rem)) & 0xFF;
            if ((ord($bin[$full]) & $mask) !== (ord($nb[$full]) & $mask)) return false;
        }
        return true;
    }

    public static function ipIsBlocked(string $ip): bool
    {
        $ip = trim($ip, '[]');
        $bin = @inet_pton($ip);
        if ($bin === false) return true;
        if (strlen($bin) === 4) {
            foreach (self::V4_BLOCKED as $c) if (self::inNet($bin, $c)) return true;
            return false;
        }
        // IPv4-mapped (::ffff:a.b.c.d) is judged as its IPv4 address
        if (substr($bin, 0, 12) === str_repeat("\0", 10) . "\xff\xff") return self::ipIsBlocked(inet_ntop(substr($bin, 12)));
        if (!self::inNet($bin, '2000::/3')) return true;  // only global unicast is allowed
        foreach (self::V6_BLOCKED as $c) {
            if (!self::inNet($bin, $c)) continue;
            if ($c === '2002::/16') {  // 6to4: judge the embedded IPv4
                return self::ipIsBlocked(inet_ntop(substr($bin, 2, 4)));
            }
            return true;
        }
        return false;
    }

    public static function hostNameIsBlocked(string $host): bool
    {
        $h = strtolower(rtrim(trim($host, '[]'), '.'));
        if (in_array($h, ['localhost', 'localhost.localdomain', 'ip6-localhost', 'metadata', 'metadata.google.internal'], true)) return true;
        foreach (['.localhost', '.local', '.internal', '.intranet', '.lan', '.home', '.corp', '.localdomain'] as $s) {
            if (str_ends_with($h, $s)) return true;
        }
        return false;
    }

    /** @return string[] */
    public static function systemResolver(string $host, int $port): array
    {
        $ips = [];
        $v4 = @gethostbynamel($host);
        if (is_array($v4)) $ips = $v4;
        $v6 = @dns_get_record($host, DNS_AAAA);
        if (is_array($v6)) foreach ($v6 as $r) if (!empty($r['ipv6'])) $ips[] = $r['ipv6'];
        return array_values(array_unique($ips));
    }

    /**
     * Returns the safe IP list or throws SsrfBlocked. The caller must connect to one of these IPs (not re-resolve),
     * so a DNS rebinding answer between check and connect cannot reach an internal address.
     * @return string[]
     */
    public static function checkDestination(string $host, int $port, array $allowedPorts, ?callable $resolver = null): array
    {
        $resolver ??= [self::class, 'systemResolver'];
        if (!in_array($port, $allowedPorts, true)) throw new SsrfBlocked('port_not_allowed');
        if (self::hostNameIsBlocked($host)) throw new SsrfBlocked('internal_hostname');
        $lit = U::parseIpLiteral($host);
        if ($lit !== null) {
            if (self::ipIsBlocked($lit)) throw new SsrfBlocked('private_ip');
            return [$lit];
        }
        try {
            $ips = $resolver($host, $port);
        } catch (\Throwable) {
            throw new SsrfBlocked('dns_failed');
        }
        if (!$ips) throw new SsrfBlocked('dns_failed');
        foreach ($ips as $ip) {  // one bad address in the answer blocks the whole host
            $clean = explode('%', (string)$ip)[0];
            if (@inet_pton($clean) === false) throw new SsrfBlocked('dns_bad_answer');
            if (self::ipIsBlocked($clean)) throw new SsrfBlocked('resolves_to_private_ip');
        }
        return array_values($ips);
    }
}
