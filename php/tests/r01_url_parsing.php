<?php
use P2\{U, BadUrl};
return [
 'lowercases host and scheme' => fn() => eq(U::normalize('HTTP://ExAmple.COM/A'), 'http://example.com/A'),
 'adds http and path' => fn() => eq(U::normalize('example.com'), 'http://example.com/'),
 'refangs hxxp and [.]' => fn() => eq(U::normalize('hxxps://example[.]com/x'), 'https://example.com/x'),
 'drops fragment keeps query' => fn() => eq(U::normalize('http://a.com/p?q=1#frag'), 'http://a.com/p?q=1'),
 'strips zero width and control chars' => fn() => eq(U::normalize("http://exa\u{200b}mple.com/\x00"), 'http://example.com/'),
 'rejects other schemes' => function () { foreach (['ftp://a.com', 'javascript:alert(1)', 'file:///etc/passwd', 'data:text/html,x', 'gopher://a.com'] as $u) raises(BadUrl::class, fn() => U::normalize($u), $u); },
 'accepts host:port without scheme' => fn() => eq(U::normalize('example.com:8080/x'), 'http://example.com:8080/x'),
 'rejects empty and non text' => function () { raises(BadUrl::class, fn() => U::normalize('')); raises(BadUrl::class, fn() => U::normalize(null)); raises(BadUrl::class, fn() => U::normalize(['a'])); },
 'rejects too long' => fn() => raises(BadUrl::class, fn() => U::normalize('http://a.com/' . str_repeat('a', 3000))),
 'rejects bad port' => function () { raises(BadUrl::class, fn() => U::normalize('http://a.com:99999/')); raises(BadUrl::class, fn() => U::normalize('http://a.com:ab/')); },
 'rejects illegal host chars' => function () { foreach (['http://a<b.com/', 'http://a"b.com/', 'http://a{b}.com/'] as $u) raises(BadUrl::class, fn() => U::normalize($u), $u); },
 'idn becomes punycode' => fn() => eq(U::normalize('http://bücher.de/'), 'http://xn--bcher-kva.de/'),
 'arabic idn works' => fn() => check(str_starts_with(U::normalize('http://مثال.com/'), 'http://xn--')),
 'ip forms normalised' => function () { foreach (['http://2130706433/', 'http://0x7f000001/', 'http://017700000001/', 'http://127.1/', 'http://0x7f.0.0.1/'] as $u) eq(U::normalize($u), 'http://127.0.0.1/', $u); },
 'ipv6 kept in brackets' => fn() => eq(U::normalize('http://[::1]:8080/'), 'http://[::1]:8080/'),
 'userinfo kept so it can be flagged' => fn() => eq(U::normalize('http://paypal.com@evil.top/x'), 'http://paypal.com@evil.top/x'),
 'defang and refang roundtrip' => function () { eq(U::defang('https://a.com/x'), 'hxxps://a[.]com/x'); eq(U::refang('hxxps://a[.]com'), 'https://a.com'); },
 'fragment trick uses real host' => fn() => eq(U::hostOf(U::normalize('http://evil.com#@127.0.0.1/')), 'evil.com'),
 'join resolves relative' => function () { eq(U::join('http://a.com/x/y', '../z'), 'http://a.com/z'); eq(U::join('http://a.com/x/y', '/q?w=1'), 'http://a.com/q?w=1'); eq(U::join('http://a.com/x', '//b.com/c'), 'http://b.com/c'); eq(U::join('https://a.com/x', 'http://b.com/'), 'http://b.com/'); },
];
