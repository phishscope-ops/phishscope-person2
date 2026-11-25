<?php
use P2\{VirusTotal, LocalBlocklist, IntelHub, IntelResult, Intel};
function vt(int $code, string $body, array $o = ['vtApiKey' => 'k'], ?array &$n = null): VirusTotal { $n = [0]; return new VirusTotal(cfg($o), function () use ($code, $body, &$n) { $n[0]++; return [$code, $body]; }); }
function vtbody(int $m, int $s = 0): string { return json_encode(['data' => ['attributes' => ['last_analysis_stats' => ['malicious' => $m, 'suspicious' => $s, 'harmless' => 60]]]]); }
return [
 'no key is unavailable not safe' => fn() => eq(vt(200, '', ['vtApiKey' => ''])->check('http://a.com/')->state, 'unavailable'),
 '2 engines is malicious' => function () { $r = vt(200, vtbody(2))->check('http://a.com/'); eq([$r->state, $r->verdict], ['confirmed', 'malicious']); },
 '1 engine is suspicious' => fn() => eq(vt(200, vtbody(1))->check('http://a.com/')->verdict, 'suspicious'),
 'only suspicious engines is suspicious' => fn() => eq(vt(200, vtbody(0, 2))->check('http://a.com/')->verdict, 'suspicious'),
 'zero detections is inconclusive never safe' => function () { $r = vt(200, vtbody(0))->check('http://a.com/'); eq($r->state, 'inconclusive'); eq($r->verdict, null); },
 '404 inconclusive' => fn() => eq(vt(404, '')->check('http://a.com/')->state, 'inconclusive'),
 '429 quota unavailable' => fn() => eq(vt(429, '')->check('http://a.com/')->detail, 'quota_exceeded'),
 '500 unavailable' => fn() => eq(vt(500, '')->check('http://a.com/')->state, 'unavailable'),
 'garbage body unavailable' => fn() => eq(vt(200, 'not json')->check('http://a.com/')->state, 'unavailable'),
 'network exception unavailable' => fn() => eq((new VirusTotal(cfg(['vtApiKey' => 'k']), fn() => throw new RuntimeException('x')))->check('http://a.com/')->state, 'unavailable'),
 'results are cached' => function () { $n = null; $v = vt(200, vtbody(0), ['vtApiKey' => 'k'], $n); $v->check('http://a.com/'); $v->check('http://a.com/'); eq($n[0], 1); },
 'blocklist domain and subdomain match' => function () { $f = tempnam(sys_get_temp_dir(), 'bl'); file_put_contents($f, "# c\nevil.top\nhttp://x.com/bad\n"); $b = new LocalBlocklist($f);
   eq($b->check('http://evil.top/')->verdict, 'malicious'); eq($b->check('http://a.b.evil.top/x')->verdict, 'malicious'); eq($b->check('http://x.com/bad')->verdict, 'malicious'); eq($b->check('http://good.com/')->state, 'inconclusive'); unlink($f); },
 'missing blocklist unavailable' => fn() => eq((new LocalBlocklist('/nonexistent'))->check('http://a.com/')->state, 'unavailable'),
 'registered domain handles eg' => function () { eq(Intel::registeredDomain('a.b.com.eg'), 'b.com.eg'); eq(Intel::registeredDomain('a.b.example.com'), 'example.com'); },
 'hub checks every hop' => function () { $seen = []; $p = new class($seen) { public string $name = 'p'; public function __construct(public array &$s) {} public function check(string $u): IntelResult { $this->s[] = $u; return new IntelResult('p', 'inconclusive'); } };
   (new IntelHub(cfg(), [$p]))->lookup(['http://a.com/', 'http://b.com/']); eq(count($seen), 2); },
 'hub survives provider exception' => function () { $p = new class { public string $name = 'p'; public function check(string $u): IntelResult { throw new RuntimeException('x'); } };
   $r = (new IntelHub(cfg(), [$p]))->lookup(['http://a.com/']); eq($r[0]->state, 'unavailable'); },
];
