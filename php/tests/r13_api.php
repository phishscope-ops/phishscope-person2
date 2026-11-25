<?php
use P2\LogSafe;
return [
 'health open without key' => function () { [$c, $r] = call(api(['apiKey' => 'K']), 'GET', '/health'); eq($c, 200); eq($r['status'], 'ok'); },
 'health does not leak keys' => function () { [$c, $r] = call(api(['apiKey' => 'SECRETKEY', 'vtApiKey' => 'VTSECRET']), 'GET', '/health'); $j = json_encode($r); check(!str_contains($j, 'SECRETKEY') && !str_contains($j, 'VTSECRET')); },
 '401 without key' => fn() => eq(call(api(['apiKey' => 'K']), 'POST', '/v1/urls/scan', ['url' => 'http://a.com'])[0], 401),
 '401 wrong key' => fn() => eq(call(api(['apiKey' => 'K']), 'POST', '/v1/urls/scan', ['url' => 'http://a.com'], ['x-api-key' => 'nope'])[0], 401),
 'right key works' => fn() => eq(call(api(['apiKey' => 'K']), 'POST', '/v1/urls/scan', ['url' => 'https://example.com/'], ['x-api-key' => 'K'])[0], 202),
 'no key configured means open' => fn() => eq(call(api(), 'POST', '/v1/urls/scan', ['url' => 'https://example.com/'])[0], 202),
 '404 unknown route and method' => function () { eq(call(api(), 'GET', '/nope')[0], 404); eq(call(api(), 'GET', '/v1/urls/scan')[0], 404); eq(call(api(), 'DELETE', '/v1/urls/scan')[0], 404); },
 '422 bad bodies' => function () { foreach (['', 'not json', '[1,2]', '{"url":5}', '{}', '{"url":""}', '{"url":"' . str_repeat('a', 5000) . '"}', '{"url":null}'] as $b) eq(call(api(), 'POST', '/v1/urls/scan', $b)[0], 422, $b); },
 '422 bad client_ref' => function () { eq(call(api(), 'POST', '/v1/urls/scan', ['url' => 'http://a.com', 'client_ref' => 5])[0], 422); eq(call(api(), 'POST', '/v1/urls/scan', ['url' => 'http://a.com', 'client_ref' => str_repeat('x', 200)])[0], 422); },
 'client_ref echoed' => function () { [$c, $r] = call(api(), 'POST', '/v1/urls/scan', ['url' => 'https://example.com/', 'client_ref' => 'scan-77']); eq($r['result']['client_ref'], 'scan-77'); },
 'post returns scan id and poll works' => function () { $a = api(); [$c, $r] = call($a, 'POST', '/v1/urls/scan', ['url' => 'https://example.com/']); eq($c, 202); [$c2, $r2] = call($a, 'GET', $r['poll_url']); eq($c2, 200); eq($r2['status'], 'completed'); eq($r2['result']['verdict'], 'safe'); },
 'unknown scan id 404' => fn() => eq(call(api(), 'GET', '/v1/scans/nonexistent')[0], 404),
 'scan id path injection is just 404' => function () { foreach (['/v1/scans/..%2f..%2fetc', "/v1/scans/' OR 1=1 --", '/v1/scans/a/b'] as $p) eq(call(api(), 'GET', $p)[0], 404, $p); },
 'rate limit 429' => function () { $a = api(['rateLimitPerMinute' => 3]); $codes = []; for ($i = 0; $i < 5; $i++) $codes[] = call($a, 'GET', '/v1/scans/x')[0]; eq($codes, [404, 404, 404, 429, 429]); },
 'rate limit is per client' => function () { $c = cfg(['rateLimitPerMinute' => 1]); $a = new P2\Api($c, scanner(), new P2\Store(':memory:')); $a->handle('GET', '/v1/scans/x', [], '', '1.1.1.1'); eq($a->handle('GET', '/v1/scans/x', [], '', '2.2.2.2')[0], 404); eq($a->handle('GET', '/v1/scans/x', [], '', '1.1.1.1')[0], 429); },
 '413 oversized email' => fn() => eq(call(api(['maxEmailBytes' => 50]), 'POST', '/v1/emails/scan', ['eml_text' => str_repeat('a', 100)])[0], 413),
 '422 email missing or bad base64' => function () { eq(call(api(), 'POST', '/v1/emails/scan', [])[0], 422); eq(call(api(), 'POST', '/v1/emails/scan', ['eml_base64' => '@@@'])[0], 422); },
 'email via base64 works' => function () { [$c, $r] = call(api(), 'POST', '/v1/emails/scan', ['eml_base64' => base64_encode("From: a@b.com\r\nSubject: hi\r\nContent-Type: text/plain\r\n\r\nسلام")]); eq($c, 202); check(isset($r['result']['attachments'])); },
 'sms scan works' => function () { [$c, $r] = call(api(), 'POST', '/v1/sms/scan', ['body' => 'hello', 'sender' => '+201000000000']); eq($c, 202); eq($r['result']['verdict'], 'safe'); },
 'result has handoff fields' => function () { [$c, $r] = call(api(), 'POST', '/v1/urls/scan', ['url' => '127.0.0.1']); $x = $r['result']; check(isset($x['severity'], $x['scanner_verdict'], $x['evidence_items'])); eq($x['scanner_verdict'], $x['verdict']); },
 'internal errors give 500 without details' => function () { $sc = scanner(); $sc->fetcher = new class(cfg()) extends P2\Fetcher { public function trace(string $u, ?float $d = null): P2\Trace { throw new RuntimeException('secret path /etc/x'); } };
   [$c, $r] = call(api([], $sc), 'POST', '/v1/urls/scan', ['url' => 'http://a.com/']); eq($r['status'], 'completed'); eq($r['result']['verdict'], 'unknown'); check(!str_contains(json_encode($r), '/etc/x')); },
 'logs never contain keys, emails, phones, query strings' => function () {
   LogSafe::$captured = []; LogSafe::error('fail Authorization: Bearer abcdefghijklmnop user a@b.com phone +201012345678 url http://x.com/p?token=SECRET123 x-apikey: ABCDEF'); $l = implode(' ', LogSafe::$captured);
   foreach (['abcdefghijklmnop', 'a@b.com', '01012345678', 'SECRET123', 'ABCDEF'] as $s) check(!str_contains($l, $s), $s); },
 'long hex and key tokens scrubbed' => function () { $l = LogSafe::scrub('k=' . str_repeat('a1', 30) . ' z ' . str_repeat('Zz_', 15)); check(!str_contains($l, 'a1a1a1a1a1a1')); },
 'sms body never appears in api error log' => function () { LogSafe::$captured = []; $sc = scanner(); $sc->engines = new class(cfg()) extends P2\Engines { public function analyze(string $k, string $c, array $x): P2\EngineResult { throw new RuntimeException('body was: ' . $c); } };
   call(api([], $sc), 'POST', '/v1/protection/sms', ['body' => 'كلمة السر المميزة']); check(!str_contains(implode(' ', LogSafe::$captured), 'المميزة')); },
 'sql injection in client_ref is stored inert' => function () { $a = api(); [$c, $r] = call($a, 'POST', '/v1/urls/scan', ['url' => 'https://example.com/', 'client_ref' => "x'); DROP TABLE scans;--"]); eq($c, 202); eq(call($a, 'GET', $r['poll_url'])[0], 200); },
];
