<?php
use P2\Verdict;
return [
 'direct 200 is complete' => function () { $s = scanner(); $t = $s->fetcher->trace('http://a.example/'); check($t->complete && $t->error === ''); eq(count($t->hops), 1); },
 'follows chain and records every hop' => function () {
   $w = new FakeWeb(['http://a.example/' => [301, 'http://b.example/'], 'http://b.example/' => [302, '/c']]);
   $s = scanner([], $w); $t = $s->fetcher->trace('http://a.example/');
   eq($t->chain(), ['http://a.example/', 'http://b.example/', 'http://b.example/c']); check($t->complete); },
 'connects to the vetted ip not the name' => function () { $w = new FakeWeb(); scanner([], $w, ['a.example' => '8.8.4.4'])->fetcher->trace('http://a.example/'); eq($w->calls[0]['ip'], '8.8.4.4'); eq($w->calls[0]['host'], 'a.example'); },
 'internal redirect target is never fetched' => function () {
   $w = new FakeWeb(['http://a.example/' => [302, 'http://127.0.0.1/admin']]); $t = scanner([], $w)->fetcher->trace('http://a.example/');
   eq($t->blockedReason, 'private_ip'); eq(count($w->calls), 1); check(!$t->complete); },
 'redirect to metadata ip blocked' => function () { $w = new FakeWeb(['http://a.example/' => [302, 'http://169.254.169.254/latest']]); eq(scanner([], $w)->fetcher->trace('http://a.example/')->blockedReason, 'private_ip'); },
 'redirect to host that resolves private blocked' => function () {
   $w = new FakeWeb(['http://a.example/' => [302, 'http://rebind.example/']]); $t = scanner([], $w, ['rebind.example' => '10.0.0.9'])->fetcher->trace('http://a.example/');
   eq($t->blockedReason, 'resolves_to_private_ip'); eq(count($w->calls), 1); },
 'redirect to bad port blocked' => function () { $w = new FakeWeb(['http://a.example/' => [302, 'http://b.example:22/']]); eq(scanner([], $w)->fetcher->trace('http://a.example/')->blockedReason, 'port_not_allowed'); },
 'redirect to non http scheme is a bad target' => function () { $w = new FakeWeb(['http://a.example/' => [302, 'ftp://b.example/']]); eq(scanner([], $w)->fetcher->trace('http://a.example/')->error, 'bad_redirect_target'); },
 'loop detected' => function () { $w = new FakeWeb(['http://a.example/' => [302, 'http://b.example/'], 'http://b.example/' => [302, 'http://a.example/']]); eq(scanner([], $w)->fetcher->trace('http://a.example/')->error, 'redirect_loop'); },
 'too many redirects stops at the limit' => function () {
   $r = []; for ($i = 0; $i < 20; $i++) $r["http://s$i.example/"] = [302, 'http://s' . ($i + 1) . '.example/'];
   $w = new FakeWeb($r); $t = scanner(['maxRedirects' => 5], $w)->fetcher->trace('http://s0.example/'); eq($t->error, 'too_many_redirects'); eq(count($w->calls), 6); },
 'fetch errors map to codes' => function () { foreach (['timeout', 'connect_error', 'tls_error', 'http_error'] as $e) eq(scanner([], new FakeWeb([], 200, $e))->fetcher->trace('http://a.example/')->error, $e); },
 'a failed trace never gives safe' => function () { $r = scanner([], new FakeWeb([], 200, 'timeout'))->scanUrl('http://a.example/'); check($r['verdict'] !== 'safe'); eq($r['verdict'], 'unknown'); },
 'redirect chain to internal never gives safe' => function () { $w = new FakeWeb(['http://a.example/' => [302, 'http://127.0.0.1/']]); check(scanner([], $w)->scanUrl('http://a.example/')['verdict'] !== 'safe'); },
 'userinfo is not sent to the fetcher url used for pinning' => function () { $w = new FakeWeb(); scanner([], $w)->fetcher->trace('http://paypal.com@evil.example/'); eq($w->calls[0]['host'], 'evil.example'); },
 'deadline already passed gives timeout' => function () { $t = scanner()->fetcher->trace('http://a.example/', microtime(true) - 1); eq($t->error, 'timeout'); },
];
