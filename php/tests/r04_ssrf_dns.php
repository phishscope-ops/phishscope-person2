<?php
use P2\{Ssrf, SsrfBlocked};
$ports = [80, 443, 8080, 8443];
return [
 'public host passes and returns ips' => fn() => eq(Ssrf::checkDestination('example.com', 443, $ports, resolver()), [PUBLIC_IP]),
 'private answer blocked' => fn() => raises(SsrfBlocked::class, fn() => Ssrf::checkDestination('evil.com', 80, $ports, resolver(['evil.com' => '10.0.0.5']))),
 'one bad address in a mixed answer blocks all (rebinding)' => fn() => raises(SsrfBlocked::class, fn() => Ssrf::checkDestination('evil.com', 80, $ports, resolver(['evil.com' => [PUBLIC_IP, '127.0.0.1']]))),
 'ipv6 loopback answer blocked' => fn() => raises(SsrfBlocked::class, fn() => Ssrf::checkDestination('evil.com', 80, $ports, resolver(['evil.com' => '::1']))),
 'dns failure blocks' => fn() => raises(SsrfBlocked::class, fn() => Ssrf::checkDestination('nx.example', 80, $ports, resolver(['nx.example' => null]))),
 'empty answer blocks' => fn() => raises(SsrfBlocked::class, fn() => Ssrf::checkDestination('e.example', 80, $ports, fn() => [])),
 'bad port blocked' => function () use ($ports) { foreach ([22, 25, 3306, 6379, 9200, 8000] as $p) raises(SsrfBlocked::class, fn() => Ssrf::checkDestination('example.com', $p, $ports, resolver()), (string)$p); },
 'ip literal checked without dns' => function () use ($ports) { raises(SsrfBlocked::class, fn() => Ssrf::checkDestination('127.0.0.1', 80, $ports, fn() => throw new Exception('dns used'))); },
 'tricky literals blocked' => function () use ($ports) { foreach (['2130706433', '0x7f000001', '127.1', '[::ffff:7f00:1]', '[::1]'] as $h) raises(SsrfBlocked::class, fn() => Ssrf::checkDestination($h, 80, $ports, resolver()), $h); },
 'metadata name blocked before dns' => fn() => raises(SsrfBlocked::class, fn() => Ssrf::checkDestination('metadata.google.internal', 80, $ports, fn() => [PUBLIC_IP])),
 'bad dns answer blocked' => fn() => raises(SsrfBlocked::class, fn() => Ssrf::checkDestination('x.example', 80, $ports, fn() => ["garbage"])),
];
