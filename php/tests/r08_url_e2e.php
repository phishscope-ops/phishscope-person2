<?php
use P2\IntelResult;
$mal = new class { public string $name = 'bl'; public function check(string $u): IntelResult { return str_contains($u, 'bad.example') ? new IntelResult('bl', 'confirmed', 'malicious') : new IntelResult('bl', 'inconclusive'); } };
return [
 'plain legit url is safe with full trace' => function () { $r = scanner()->scanUrl('https://example.com/'); eq($r['verdict'], 'safe'); eq($r['action'], 'allow'); check($r['evidence']['redirects']['complete']); eq($r['evidence']['redirects']['https_used'], true); },
 'result is defanged' => function () { $r = scanner()->scanUrl('https://example.com/x'); eq($r['url_defanged'], 'hxxps://example[.]com/x'); },
 'suspicious tld and keywords not safe' => function () { $r = scanner()->scanUrl('http://secure-paypal-login.top/verify/account'); check($r['verdict'] !== 'safe'); },
 'brand impersonation not safe' => function () { $r = scanner()->scanUrl('http://paypal.com.account-verify.xyz/login'); check($r['verdict'] !== 'safe', $r['verdict']); },
 'userinfo trick not safe' => function () { check(scanner()->scanUrl('http://paypal.com@evil-site.top/login')['verdict'] !== 'safe'); },
 'raw ip host not safe' => function () { $r = scanner()->scanUrl('http://93.184.216.34/login'); check($r['verdict'] !== 'safe'); },
 'private ip is suspicious and explained' => function () { $r = scanner()->scanUrl('http://127.0.0.1/'); eq($r['verdict'], 'suspicious'); eq($r['evidence']['redirects']['blocked_reason'], 'private_ip'); },
 'bad input gives unknown not exception' => function () { foreach ([null, '', 'javascript:alert(1)', 'ftp://a.com', str_repeat('a', 5000)] as $x) { $r = scanner()->scanUrl($x); eq($r['verdict'], 'unknown'); } },
 'known bad intel on a middle hop is malicious' => function () use ($mal) {
   $w = new FakeWeb(['http://ok.example/' => [302, 'http://bad.example/x'], 'http://bad.example/x' => [302, 'http://fine.example/']]);
   $r = scanner([], $w, null, null, [$mal])->scanUrl('http://ok.example/'); eq($r['verdict'], 'malicious'); eq($r['action'], 'block'); },
 'dns failure is never safe' => function () { $r = scanner([], null, ['gone.example' => null])->scanUrl('http://gone.example/'); check($r['verdict'] !== 'safe'); check(!$r['evidence']['redirects']['complete']); },
 'engine also looks at the landing url' => function () { $w = new FakeWeb(['http://ok.example/' => [302, 'http://secure-login-verify.top/account/update']]); $r = scanner([], $w)->scanUrl('http://ok.example/'); check($r['verdict'] !== 'safe'); eq(count($r['evidence']['engine']), 2); },
 'shortener to a bad landing page is not safe' => function () { $w = new FakeWeb(['http://bit.ly/abc' => [302, 'http://secure-login-verify.top/account/update']]); check(scanner([], $w)->scanUrl('http://bit.ly/abc')['verdict'] !== 'safe'); },
 'trace skipped still returns complete result shape' => function () { $r = scanner()->scanUrl('https://example.com/', false); check(isset($r['verdict'], $r['risk_score'], $r['reasons'], $r['caveats'], $r['evidence'])); },
 'arabic idn homograph not safe' => function () { check(scanner()->scanUrl('http://pаypal.com/login')['verdict'] !== 'safe'); },
 'result is json encodable' => function () { $r = scanner()->scanUrl('https://example.com/'); check(json_encode($r, JSON_UNESCAPED_UNICODE) !== false); },
];
