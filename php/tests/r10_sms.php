<?php
return [
 'plain friendly sms is safe' => fn() => eq(scanner()->scanSms('هتيجي النهارده؟')['verdict'], 'safe'),
 'otp phishing with link not safe' => function () { $r = scanner()->scanSms('كود التحقق 482913 لا تشاركه. لتأكيد العملية ادخل http://bit.ly/3xYz'); check($r['verdict'] !== 'safe'); },
 'fake bank suspension' => function () { $r = scanner()->scanSms('تم إيقاف حسابك البنكي، اضغط فورا http://nbe-secure-verify.top/login لتحديث بياناتك'); check(in_array($r['verdict'], ['suspicious', 'malicious'], true)); eq($r['action'] === 'block' || $r['action'] === 'warn', true); },
 'prize scam' => function () { $r = scanner()->scanSms('مبروك ربحت جايزة! اضغط http://claim-prize.xyz/gift'); check($r['verdict'] !== 'safe'); },
 'parcel customs fee' => function () { $r = scanner()->scanSms('طرد باسمك عليه جمارك، ادفع خلال 24 ساعة http://aramex-pay.click/p'); check($r['verdict'] !== 'safe'); },
 'english scam' => function () { $r = scanner()->scanSms('URGENT: verify your account http://paypal-secure-login.top/'); check($r['verdict'] !== 'safe'); },
 'malicious link in otherwise clean text still wins' => function () { $bl = new class { public string $name = 'bl'; public function check(string $u): P2\IntelResult { return new P2\IntelResult('bl', 'confirmed', 'malicious'); } };
   $r = scanner([], null, null, null, [$bl])->scanSms('شوف الصورة http://pics.example/a'); eq($r['verdict'], 'malicious'); eq($r['action'], 'block'); },
 'link count and links list' => function () { $r = scanner()->scanSms('a http://a.example/ b http://b.example/'); eq($r['link_count'], 2); eq(count($r['links']), 2); },
 'links per message capped' => function () { $t = implode(' ', array_map(fn($i) => "http://s$i.example/", range(1, 40))); check(count(scanner()->scanSms($t)['links']) <= 10); },
 'long body truncated and safe from crash' => fn() => check(isset(scanner(['maxSmsLen' => 100])->scanSms(str_repeat('x', 5000))['verdict'])),
 'invalid utf8 does not crash' => fn() => check(isset(scanner()->scanSms("abc \xff\xfe http://a.example/")['verdict'])),
 'empty body ok' => fn() => check(isset(scanner()->scanSms('')['verdict'])),
 'unavailable remote engine never makes sms safe' => function () { $r = scanner(['engineUrlBase' => 'http://e'], null, null, fn() => throw new RuntimeException('down'))->scanSms('كود 1234 اضغط http://a.example/'); check($r['verdict'] !== 'safe'); },
 'link to internal address is not safe' => fn() => check(scanner()->scanSms('http://169.254.169.254/latest/meta-data')['verdict'] !== 'safe'),
];
