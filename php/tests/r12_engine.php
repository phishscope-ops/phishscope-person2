<?php
use P2\Engines;
function eng(callable $post, array $o = []): Engines { return new Engines(cfg(array_merge(['engineUrlBase' => 'http://engine'], $o)), $post); }
$good = fn(array $d) => fn() => [200, json_encode($d)];
return [
 'valid remote answer used' => function () use ($good) { $r = eng($good(['score' => 0.9, 'label' => 'phishing', 'engine' => 'm', 'version' => '2', 'reasons' => ['x']]))->analyze('url', 'http://a/', []); eq($r->state, 'ok'); eq($r->label, 'phishing'); eq($r->engine, 'm'); },
 'remote sends bearer key and kind path' => function () { $seen = []; eng(function ($u, $b, $h, $t) use (&$seen) { $seen = [$u, $h]; return [200, json_encode(['score' => 0.1, 'label' => 'legit'])]; }, ['engineApiKey' => 'KEY'])->analyze('sms', 'x', []); eq($seen[0], 'http://engine/analyze/sms'); eq($seen[1], ['Authorization: Bearer KEY']); },
 'non 200 degrades to local not safe by itself' => function () { $r = eng(fn() => [500, ''])->analyze('url', 'http://a/', []); eq($r->state, 'degraded'); check(str_contains($r->detail, 'http_500')); },
 'exception degrades' => fn() => eq(eng(fn() => throw new RuntimeException('x'))->analyze('url', 'http://a/', [])->state, 'degraded'),
 'malformed answers rejected' => function () { foreach (['nope', '[]', '{"score":2,"label":"legit"}', '{"score":-1,"label":"legit"}', '{"score":"0.5","label":"legit"}', '{"score":0.5,"label":"bogus"}', '{"label":"legit"}', 'null'] as $b) eq(eng(fn() => [200, $b])->analyze('url', 'http://a/', [])->state, 'degraded', $b); },
 'reasons capped and trimmed' => function () { $r = Engines::valid(['score' => 0.5, 'label' => 'legit', 'reasons' => array_fill(0, 50, str_repeat('x', 1000))]); eq(count($r->reasons), 10); eq(mb_strlen($r->reasons[0]), 300); },
 'label case insensitive' => fn() => eq(Engines::valid(['score' => 0.5, 'label' => 'PHISHING'])->label, 'phishing'),
 'degraded engine blocks safe verdict end to end' => function () { $r = scanner(['engineUrlBase' => 'http://e'], null, null, fn() => [503, ''])->scanUrl('https://example.com/'); check($r['verdict'] !== 'safe'); },
 'remote says legit and everything else clean is safe' => function () use ($good) { eq(scanner(['engineUrlBase' => 'http://e'], null, null, $good(['score' => 0.02, 'label' => 'legit']))->scanUrl('https://example.com/')['verdict'], 'safe'); },
 'remote says phishing is malicious' => function () use ($good) { eq(scanner(['engineUrlBase' => 'http://e'], null, null, $good(['score' => 0.97, 'label' => 'phishing']))->scanUrl('https://example.com/')['verdict'], 'malicious'); },
 'no engine url uses local heuristics' => fn() => eq((new Engines(cfg()))->analyze('url', 'http://a.com/', [])->engine, 'p2-local-heuristics'),
 'heuristics: https does not lower score' => function () { $a = Engines::urlHeuristics('http://login-verify.top/account', [])[0]; $b = Engines::urlHeuristics('https://login-verify.top/account', [])[0]; check($b >= $a - 0.06); },
];
