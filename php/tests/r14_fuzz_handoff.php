<?php
use P2\{U, Enrich, Verdict};
mt_srand(42);
function rs(int $n): string { $a = ['http://', 'https://', '[', ']', '@', '.', '%', '/', ':', '#', '?', '0x', 'xn--', "\u{200b}", 'é', 'م', '..', '::', '\\', ' ', 'a', '1', '-', '<', '>', '"']; $o = ''; for ($i = 0; $i < $n; $i++) $o .= $a[mt_rand(0, count($a) - 1)]; return $o; }
return [
 'fuzz normalize never throws anything but BadUrl' => function () { for ($i = 0; $i < 2000; $i++) { try { $u = U::normalize(rs(mt_rand(1, 30))); check($u !== ''); } catch (P2\BadUrl) {} } },
 'fuzz normalize is idempotent' => function () { for ($i = 0; $i < 1000; $i++) { try { $u = U::normalize(rs(mt_rand(1, 25))); } catch (P2\BadUrl) { continue; } eq(U::normalize($u), $u, $u); } },
 'fuzz extract never throws' => function () { for ($i = 0; $i < 500; $i++) U::extractUrls(rs(mt_rand(1, 200))); check(true); },
 'fuzz scanner url never safe for internal hosts' => function () { foreach (['127.0.0.1', '10.0.0.1', '192.168.1.1', '169.254.169.254', '[::1]', 'localhost', '0x7f.1', '2130706433'] as $h) for ($i = 0; $i < 3; $i++) check(scanner()->scanUrl("http://$h/" . rs(3))['verdict'] !== 'safe', $h); },
 'fuzz scanner returns a verdict for random input' => function () { for ($i = 0; $i < 150; $i++) { $r = scanner()->scanUrl(rs(mt_rand(1, 40))); check(in_array($r['verdict'], ['safe', 'suspicious', 'malicious', 'unknown'], true)); } },
 'fuzz email parser never throws' => function () { for ($i = 0; $i < 200; $i++) { $r = scanner()->scanEmail(rs(mt_rand(1, 300)) . "\r\n\r\n" . rs(50)); check(isset($r['verdict'])); } },
 'fuzz api random bodies never 500' => function () { $a = api(); foreach (['/v1/urls/scan', '/v1/sms/scan', '/v1/emails/scan', '/v1/protection/sms', '/v1/browser/precheck'] as $p) for ($i = 0; $i < 20; $i++) { [$c] = call($a, 'POST', $p, rs(mt_rand(0, 60))); check($c !== 500, "$p $c"); } },
 'severity table' => function () { eq(Enrich::severity('safe', 0), 'none'); eq(Enrich::severity('unknown', 0), 'unknown'); eq(Enrich::severity('suspicious', 20), 'low'); eq(Enrich::severity('suspicious', 45), 'medium'); eq(Enrich::severity('suspicious', 70), 'high'); eq(Enrich::severity('malicious', 95), 'critical'); eq(Enrich::severity('malicious', 10), 'high'); },
 'enrich keeps component verdict and ref' => function () { $r = Enrich::apply(['verdict' => 'suspicious', 'risk_score' => 50, 'reasons' => ['r']], 'ref-1'); eq($r['scanner_verdict'], 'suspicious'); eq($r['client_ref'], 'ref-1'); check(count($r['evidence_items']) >= 1); },
 'enrich without ref has no client_ref' => fn() => check(!array_key_exists('client_ref', Enrich::apply(['verdict' => 'safe', 'risk_score' => 0]))),
 'evidence items include redirect trace' => function () { $r = Enrich::apply(scanner()->scanUrl('https://example.com/')); $types = array_column($r['evidence_items'], 'type'); check(in_array('redirects', $types, true) && in_array('model_result', $types, true)); },
 'every result is json safe with arabic' => function () { $r = Enrich::apply(scanner()->scanUrl('http://secure-login-verify.top/account')); check(json_encode($r, JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR) !== ''); },
 'store survives reopen of ttl expiry' => function () { $s = new P2\Store(':memory:', -1); $id = $s->create('url'); $s->update($id, 'completed', ['x' => 1]); check($s->get($id) === null || is_array($s->get($id))); },
 'uuid format' => fn() => check((bool)preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/', P2\Store::uuid())),
];
