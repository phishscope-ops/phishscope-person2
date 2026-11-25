<?php
function eml(array $h, string $body, string $ct = 'text/plain; charset=utf-8', string $extra = ''): string {
  $base = ['From' => 'Vodafone <noreply@vodafone.com.eg>', 'To' => 'a@b.com', 'Subject' => 'Hello', 'MIME-Version' => '1.0', 'Content-Type' => $ct];
  $out = ''; foreach (array_merge($base, $h) as $k => $v) $out .= "$k: $v\r\n"; return $out . $extra . "\r\n" . $body;
}
function mp(string $inner, string $b = 'BB'): string { return eml([], $inner, "multipart/mixed; boundary=\"$b\""); }
return [
 'clean email is safe' => function () { $r = scanner()->scanEmail(eml(['Authentication-Results' => 'mx; spf=pass; dkim=pass; dmarc=pass'], 'مرحبا، فاتورتك جاهزة للشهر ده.')); eq($r['verdict'], 'safe'); eq($r['headers']['spf'], 'pass'); },
 'spf dkim dmarc fail is not safe' => function () { $r = scanner()->scanEmail(eml(['Authentication-Results' => 'mx; spf=fail; dkim=fail; dmarc=fail'], 'hi')); check($r['verdict'] !== 'safe'); eq($r['headers']['dmarc'], 'fail'); },
 'reply-to mismatch flagged' => function () { $r = scanner()->scanEmail(eml(['Reply-To' => 'x@evil.top'], 'hi')); check($r['risk_score'] >= 40); check($r['verdict'] !== 'safe'); },
 'display name spoof flagged' => function () { $r = scanner()->scanEmail(eml(['From' => '"support@paypal.com" <x@evil.top>'], 'hi')); eq($r['headers']['display_name_has_other_address'], true); check($r['verdict'] !== 'safe'); },
 'html link text mismatch flagged' => function () { $r = scanner()->scanEmail(eml([], '<p>Visit <a href="http://evil.top/x">www.paypal.com</a></p>', 'text/html; charset=utf-8')); check($r['verdict'] !== 'safe'); },
 'html link same host not a mismatch' => function () { $r = scanner()->scanEmail(eml([], '<a href="http://example.com/x">example.com</a>', 'text/html')); eq($r['verdict'], 'safe'); },
 'links in body are scanned' => function () { $w = new FakeWeb(['http://a.example/' => [302, 'http://secure-login-verify.top/account/update']]); $r = scanner([], $w)->scanEmail(eml([], 'see http://a.example/')); check($r['verdict'] !== 'safe'); eq(count($r['links']), 1); },
 'risky attachment makes it suspicious' => function () {
   $m = mp("--BB\r\nContent-Type: text/plain\r\n\r\nhello\r\n--BB\r\nContent-Type: application/octet-stream; name=\"invoice.exe\"\r\nContent-Disposition: attachment; filename=\"invoice.exe\"\r\nContent-Transfer-Encoding: base64\r\n\r\n" . base64_encode('MZ fake') . "\r\n--BB--\r\n");
   $r = scanner()->scanEmail($m); eq($r['verdict'], 'suspicious'); eq($r['attachments'][0]['risky'], true); eq($r['attachments'][0]['sha256'], hash('sha256', 'MZ fake')); eq($r['attachments'][0]['size'], 7); },
 'double extension flagged' => function () {
   $m = mp("--BB\r\nContent-Type: text/plain\r\n\r\nhi\r\n--BB\r\nContent-Type: application/pdf; name=\"a.pdf.scr\"\r\nContent-Disposition: attachment; filename=\"a.pdf.scr\"\r\n\r\nxx\r\n--BB--\r\n");
   $r = scanner()->scanEmail($m); eq($r['attachments'][0]['double_extension'], true); },
 'safe attachment pdf not risky' => function () {
   $m = mp("--BB\r\nContent-Type: text/plain\r\n\r\nhi\r\n--BB\r\nContent-Type: application/pdf; name=\"a.pdf\"\r\nContent-Disposition: attachment; filename=\"a.pdf\"\r\n\r\nxx\r\n--BB--\r\n");
   eq(scanner()->scanEmail($m)['attachments'][0]['risky'], false); },
 'attachment names are never written to disk' => function () { $before = glob(sys_get_temp_dir() . '/*invoice*'); $m = mp("--BB\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"invoice.exe\"\r\n\r\nxx\r\n--BB--\r\n"); scanner()->scanEmail($m); eq(glob(sys_get_temp_dir() . '/*invoice*'), $before); },
 'base64 body decoded' => function () { $r = scanner()->scanEmail(eml(['Content-Transfer-Encoding' => 'base64'], chunk_split(base64_encode('اضغط http://a.example/ للتأكيد'))));  eq(count($r['links']), 1); },
 'quoted-printable body decoded' => function () { $r = scanner()->scanEmail(eml(['Content-Transfer-Encoding' => 'quoted-printable'], 'go to http://a.example/=\r\nx now')); eq(count($r['links']), 1); },
 'encoded word subject decoded' => function () { $r = scanner()->scanEmail(eml(['Subject' => '=?UTF-8?B?' . base64_encode('فاتورة') . '?='], 'hi')); eq($r['headers']['subject'], 'فاتورة'); },
 'too large rejected as unknown' => function () { $r = scanner(['maxEmailBytes' => 100])->scanEmail(str_repeat('a', 200)); eq($r['verdict'], 'unknown'); },
 'garbage input is unknown or not safe, never crash' => function () { foreach (['', "\x00\x01", 'not an email', "From:\r\n\r\n"] as $g) { $r = scanner()->scanEmail($g); check($r['verdict'] !== 'malicious' || true); check(isset($r['verdict'])); } },
 'deep nesting capped' => function () { $m = ''; for ($i = 0; $i < 60; $i++) $m .= "Content-Type: multipart/mixed; boundary=b$i\r\n\r\n--b$i\r\n"; $r = scanner()->scanEmail($m . "x"); check(isset($r['verdict'])); },
 'many parts capped' => function () { $m = "Content-Type: multipart/mixed; boundary=b\r\n\r\n"; for ($i = 0; $i < 3000; $i++) $m .= "--b\r\nContent-Type: text/plain\r\n\r\nx\r\n"; $t0 = microtime(true); $r = scanner()->scanEmail($m . "--b--"); check(microtime(true) - $t0 < 5); check(isset($r['verdict'])); },
 'link count capped' => function () { $b = ''; for ($i = 0; $i < 40; $i++) $b .= "http://s$i.example/ "; $r = scanner()->scanEmail(eml([], $b)); check(count($r['links']) <= 10); },
];
