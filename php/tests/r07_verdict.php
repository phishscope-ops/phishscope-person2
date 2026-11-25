<?php
use P2\{Verdict, EngineResult, IntelResult, Trace};
function okEng(float $s = 0.05, string $l = 'legit', string $st = 'ok'): EngineResult { return new EngineResult($st, 'e', '1', $l, $s); }
function goodTrace(): Trace { $t = new Trace('http://a.com/'); $t->complete = true; return $t; }
return [
 'clean complete is safe' => fn() => eq(Verdict::judge([okEng()], [], [goodTrace()])->verdict, 'safe'),
 'safe carries a caveat when no intel' => fn() => check(count(Verdict::judge([okEng()], [], [goodTrace()])->caveats) > 0),
 'engine unavailable is unknown' => fn() => eq(Verdict::judge([new EngineResult('unavailable')], [], [goodTrace()])->verdict, 'unknown'),
 'no engines is unknown' => fn() => eq(Verdict::judge([], [], [goodTrace()])->verdict, 'unknown'),
 'degraded engine is never safe' => fn() => check(Verdict::judge([okEng(0.0, 'legit', 'degraded')], [], [goodTrace()])->verdict !== 'safe'),
 'incomplete trace is never safe' => function () { $t = new Trace('http://a.com/'); eq(Verdict::judge([okEng()], [], [$t])->verdict, 'unknown'); },
 'trace error is never safe' => function () { $t = new Trace('http://a.com/'); $t->error = 'timeout'; check(Verdict::judge([okEng()], [], [$t])->verdict !== 'safe'); },
 'blocked trace is suspicious' => function () { $t = new Trace('http://a.com/'); $t->blockedReason = 'private_ip'; eq(Verdict::judge([okEng()], [], [$t])->verdict, 'suspicious'); },
 'redirect loop is suspicious' => function () { $t = new Trace('http://a.com/'); $t->error = 'redirect_loop'; eq(Verdict::judge([okEng()], [], [$t])->verdict, 'suspicious'); },
 'confirmed malicious intel wins over a clean engine' => function () { $j = Verdict::judge([okEng()], [new IntelResult('vt', 'confirmed', 'malicious')], [goodTrace()]); eq($j->verdict, 'malicious'); check($j->riskScore >= 90); },
 'confirmed suspicious intel is suspicious' => fn() => eq(Verdict::judge([okEng()], [new IntelResult('vt', 'confirmed', 'suspicious')], [goodTrace()])->verdict, 'suspicious'),
 'unavailable intel does not make it safe or bad' => function () { $j = Verdict::judge([okEng()], [new IntelResult('vt', 'unavailable')], [goodTrace()]); eq($j->verdict, 'safe'); check(count($j->caveats) >= 1); },
 'inconclusive intel is not a malicious signal' => fn() => eq(Verdict::judge([okEng()], [new IntelResult('vt', 'inconclusive')], [goodTrace()])->verdict, 'safe'),
 'strong phishing engine is malicious' => fn() => eq(Verdict::judge([okEng(0.95, 'phishing')], [], [goodTrace()])->verdict, 'malicious'),
 'mid score is suspicious' => fn() => eq(Verdict::judge([okEng(0.5, 'suspicious')], [], [goodTrace()])->verdict, 'suspicious'),
 'extra finding raises score' => fn() => eq(Verdict::judge([okEng()], [], [goodTrace()], [['rule' => 'x', 'detail' => 'd', 'weight' => 45]])->verdict, 'suspicious'),
 'actions map' => function () { eq(Verdict::ACTIONS, ['malicious' => 'block', 'suspicious' => 'warn', 'unknown' => 'warn_unverified', 'safe' => 'allow']); },
 'score bounded 0..100' => function () { $j = Verdict::judge([okEng(5.0, 'phishing')], [new IntelResult('v', 'confirmed', 'malicious')], [goodTrace()]); check($j->riskScore <= 100 && $j->riskScore >= 0); },
 'reasons capped at 12' => function () { $ex = []; for ($i = 0; $i < 30; $i++) $ex[] = ['rule' => 'r', 'detail' => "d$i", 'weight' => 10]; check(count(Verdict::judge([okEng()], [], [goodTrace()], $ex)->reasons) <= 12); },
 'https never lowers score' => function () { $a = new Trace('https://a.com/'); $a->complete = true; eq(Verdict::judge([okEng(0.5, 'suspicious')], [], [$a])->verdict, 'suspicious'); },
];
