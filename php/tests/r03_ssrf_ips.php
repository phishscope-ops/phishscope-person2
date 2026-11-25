<?php
use P2\Ssrf;
$blocked = ['127.0.0.1', '10.1.2.3', '172.16.0.1', '172.31.255.255', '192.168.0.1', '169.254.169.254', '0.0.0.0', '100.64.0.1', '224.0.0.1', '240.0.0.1', '255.255.255.255',
  '192.0.2.5', '198.18.0.1', '::1', '::', 'fe80::1', 'fc00::1', 'fd00::1', '::ffff:127.0.0.1', '::ffff:10.0.0.1', '64:ff9b::7f00:1', '2001:db8::1', 'ff02::1', '2002:7f00:1::1', '2001:0:4136:e378:8000:63bf:3fff:fdd2'];
$allowed = ['93.184.216.34', '8.8.8.8', '1.1.1.1', '172.32.0.1', '2606:2800:220:1:248:1893:25c8:1946', '2a00:1450:4001:81d::200e', '::ffff:8.8.8.8'];
return [
 'blocked ips' => function () use ($blocked) { foreach ($blocked as $ip) check(Ssrf::ipIsBlocked($ip), $ip); },
 'public ips allowed' => function () use ($allowed) { foreach ($allowed as $ip) check(!Ssrf::ipIsBlocked($ip), $ip); },
 'garbage ip is blocked' => fn() => check(Ssrf::ipIsBlocked('not-an-ip')),
 'internal host names blocked' => function () { foreach (['localhost', 'LOCALHOST.', 'metadata.google.internal', 'printer.local', 'x.internal', 'db.corp', 'a.lan'] as $h) check(Ssrf::hostNameIsBlocked($h), $h); },
 'normal names not blocked' => function () { foreach (['example.com', 'localhost.example.com', 'internal.example.org'] as $h) check(!Ssrf::hostNameIsBlocked($h), $h); },
 '6to4 embedded public allowed' => fn() => check(!Ssrf::ipIsBlocked('2002:808:808::1')),
];
