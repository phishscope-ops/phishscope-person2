<?php
use P2\U;
return [
 'finds explicit and bare links' => function () { $u = U::extractUrls('اضغط http://a.example/x, وبعدين www.b.com/p و c.org'); eq($u, ['http://a.example/x', 'http://www.b.com/p', 'http://c.org/']); },
 'ignores email addresses' => fn() => eq(U::extractUrls('اكتبلي على ali@example.com'), []),
 'ignores file names and decimals' => fn() => eq(U::extractUrls('افتح file.txt و 3.14 و report.pdf'), []),
 'trailing punctuation removed' => fn() => eq(U::extractUrls('زور http://a.com/x.'), ['http://a.com/x']),
 'arabic trailing punctuation removed' => fn() => eq(U::extractUrls('الرابط http://a.com/x،'), ['http://a.com/x']),
 'deduplicates' => fn() => eq(count(U::extractUrls('http://a.com http://a.com http://A.com/')), 1),
 'respects limit' => function () { $t = implode(' ', array_map(fn($i) => "http://s$i.example/", range(1, 30))); eq(count(U::extractUrls($t, 10)), 10); },
 'handles hxxp defanged' => fn() => eq(U::extractUrls('hxxps://evil[.]top/login'), ['https://evil.top/login']),
 'ip link kept' => fn() => eq(U::extractUrls('http://192.168.1.1/admin'), ['http://192.168.1.1/admin']),
 'huge token does not hang' => function () { $t0 = microtime(true); U::extractUrls(str_repeat('a.', 50000) . 'com'); check(microtime(true) - $t0 < 2, 'slow'); },
 'binary garbage does not crash' => function () { for ($i = 0; $i < 50; $i++) U::extractUrls(random_bytes(500)); check(true); },
];
