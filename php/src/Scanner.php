<?php
declare(strict_types=1);
namespace P2;

/** URL, Email and SMS scanners and the Secure Browser pre-check. Everything returns plain arrays (JSON-ready). */
final class Scanner
{
    const RISKY_EXT = ['exe','scr','bat','cmd','com','pif','js','jse','vbs','vbe','wsf','ps1','msi','jar','apk','lnk','iso','img','dll','hta','docm','xlsm','pptm','html','htm','svg','chm','reg','zip','rar','7z','one','php','phtml'];
    const DOC_EXT = ['pdf','doc','docx','xls','xlsx','jpg','png','txt'];

    public Engines $engines;
    public IntelHub $intel;
    public Fetcher $fetcher;
    /** Absolute microtime after which no new network work starts (set per request by the API). */
    public ?float $deadlineAt = null;
    public mixed $web = null;  // test hook only

    public function __construct(public Config $cfg, ?Engines $engines = null, ?IntelHub $intel = null, ?Fetcher $fetcher = null)
    {
        $this->engines = $engines ?? new Engines($cfg);
        $this->intel = $intel ?? new IntelHub($cfg);
        $this->fetcher = $fetcher ?? new Fetcher($cfg);
    }

    // ------------------------------------------------------------ URL (1 to 6, 21 to 28)
    public function scanUrl(mixed $rawUrl, bool $withTrace = true): array
    {
        try {
            $url = U::normalize($rawUrl, $this->cfg->maxUrlLen);
        } catch (BadUrl $e) {
            return $this->invalid($rawUrl, $e->getMessage());
        }
        if ($withTrace) $trace = $this->fetcher->trace($url, $this->deadlineAt);
        else { $trace = new Trace($url); $trace->complete = true; }
        $chain = $trace->chain() ?: [$url];
        $ctx = ['redirect_chain' => $chain, 'final_url' => $trace->finalUrl ?: $url];
        $engs = [$this->engines->analyze('url', $url, $ctx)];
        if ($trace->finalUrl !== '' && $trace->finalUrl !== $url && $trace->blockedReason === '') {
            $engs[] = $this->engines->analyze('url', $trace->finalUrl, $ctx);  // the landing page matters too
        }
        $intel = $this->intel->lookup(array_slice(array_values(array_unique($chain)), 0, $this->cfg->maxRedirects + 1));
        $j = Verdict::judge($engs, $intel, [$trace]);
        return $this->pack($url, $j, $engs, $intel, $trace);
    }

    private function invalid(mixed $raw, string $why): array
    {
        $shown = is_string($raw) ? U::defang(mb_substr(U::utf8($raw), 0, 200)) : '';
        return ['url_defanged' => $shown, 'verdict' => Verdict::UNKNOWN, 'risk_score' => 0, 'action' => Verdict::ACTIONS['unknown'], 'confidence' => 'limited',
            'reasons' => ['الرابط غير صالح للفحص'], 'caveats' => [], 'evidence' => ['invalid_input' => $why]];
    }

    private function pack(string $url, Judgement $j, array $engs, array $intel, Trace $t): array
    {
        return [
            'url_defanged' => U::defang($url), 'verdict' => $j->verdict, 'risk_score' => $j->riskScore, 'action' => Verdict::ACTIONS[$j->verdict],
            'confidence' => $j->confidence, 'reasons' => $j->reasons, 'caveats' => $j->caveats,
            'evidence' => [
                'engine' => array_map(fn($e) => $e->toArray(), $engs),
                'threat_intel' => array_map(fn($i) => $i->toArray(), $intel),
                'redirects' => [
                    'chain_defanged' => array_map([U::class, 'defang'], $t->chain()),
                    'hop_count' => max(0, count($t->hops) - 1),
                    'final_url_defanged' => $t->finalUrl !== '' ? U::defang($t->finalUrl) : '',
                    'complete' => $t->complete, 'error' => $t->error, 'blocked_reason' => $t->blockedReason,
                    'https_used' => U::schemeOf($t->finalUrl ?: $url) === 'https',
                    'https_note' => 'HTTPS مش دليل إن الموقع آمن',
                ],
            ],
        ];
    }

    // ------------------------------------------------------------ Secure Browser (21 to 24)
    public function browserPrecheck(mixed $rawUrl): array
    {
        $prev = $this->deadlineAt;
        $this->deadlineAt = microtime(true) + $this->cfg->browserDeadline;
        try { $res = $this->scanUrl($rawUrl); } finally { $this->deadlineAt = $prev; }
        $v = $res['verdict'];
        $res['browser'] = [
            'open_allowed' => $v === Verdict::SAFE,
            'interstitial' => ['malicious' => 'block_page', 'suspicious' => 'warning_page', 'unknown' => 'unverified_notice', 'safe' => null][$v],
            'title' => ['malicious' => 'تحذير: موقع خطير', 'suspicious' => 'تحذير: موقع مشبوه', 'unknown' => 'ما قدرناش نتأكد من الموقع', 'safe' => ''][$v],
            'user_can_proceed' => in_array($v, [Verdict::SUSPICIOUS, Verdict::UNKNOWN], true),  // a malicious site has no "continue anyway" button
        ];
        return $res;
    }

    // ------------------------------------------------------------ SMS
    public function scanSms(string $body, string $sender = ''): array
    {
        $body = mb_substr(U::utf8($body), 0, $this->cfg->maxSmsLen);
        $links = U::extractUrls($body, $this->cfg->maxLinksPerItem);
        $eng = $this->engines->analyze('sms', $body, ['has_links' => (bool)$links, 'sender' => $sender]);
        return $this->combine([$eng], $this->scanLinks($links), ['link_count' => count($links)]);
    }

    // ------------------------------------------------------------ Email (7 to 12)
    public function scanEmail(string $raw): array
    {
        $unknown = fn(string $why, array $ev) => ['verdict' => Verdict::UNKNOWN, 'risk_score' => 0, 'action' => Verdict::ACTIONS['unknown'], 'confidence' => 'limited', 'reasons' => [$why], 'caveats' => [], 'evidence' => $ev];
        if (strlen($raw) > $this->cfg->maxEmailBytes) return $unknown('الإيميل أكبر من الحد المسموح', ['too_large' => true]);
        try {
            $count = 0;
            $root = Mime::parse($raw, 0, $count);
        } catch (\Throwable) {
            return $unknown('ما قدرناش نقرا الإيميل', ['parse_error' => true]);
        }
        $h = self::headerChecks($root['headers']);
        $findings = self::headerFindings($h);
        [$text, $htmlLinks, $mismatch] = self::bodyContent($root);
        $attachments = self::attachmentMeta($root);  // metadata only: never written to disk, opened or run
        $risky = array_values(array_map(fn($a) => $a['filename'], array_filter($attachments, fn($a) => $a['risky'])));
        $links = array_slice(array_values(array_unique(array_merge(U::extractUrls($text, $this->cfg->maxLinksPerItem), $htmlLinks))), 0, $this->cfg->maxLinksPerItem);
        $ctx = ['header_findings' => $findings, 'has_links' => (bool)$links, 'risky_attachments' => $risky, 'link_text_mismatch' => $mismatch];
        $eng = $this->engines->analyze('email', mb_substr($h['subject'] . "\n" . $text, 0, 20000), $ctx);
        $res = $this->combine([$eng], $this->scanLinks($links), ['link_count' => count($links)], $findings);
        $res['headers'] = array_diff_key($h, ['received_chain' => 1]);
        $res['attachments'] = $attachments;
        $res['attachment_note'] = 'المرفقات بتتفحص كبيانات بس (الاسم والنوع والحجم والبصمة)، ومبتتفتحش ولا بتتشغل';
        if ($risky) {
            $res['reasons'][] = 'فيه مرفقات بامتدادات خطيرة، متفتحهاش';
            if (Verdict::ORDER[$res['verdict']] < Verdict::ORDER['suspicious']) {
                $res['verdict'] = 'suspicious'; $res['action'] = Verdict::ACTIONS['suspicious'];
                $res['risk_score'] = max($res['risk_score'], 40);
            }
        }
        return $res;
    }

    // ------------------------------------------------------------ shared
    private function scanLinks(array $links): array
    {
        $out = [];
        foreach ($links as $u) {
            try { $out[] = $this->scanUrl($u); } catch (\Throwable) { $out[] = $this->invalid($u, 'scan_failed'); }
        }
        return $out;
    }

    private function combine(array $engs, array $linkRes, array $extra, array $findings = []): array
    {
        $own = Verdict::judge($engs, [], [], $findings);
        $verdict = $own->verdict; $score = $own->riskScore;
        $reasons = $own->reasons; $caveats = $own->caveats;
        foreach ($linkRes as $lr) {  // an own verdict of "safe" only means the text looked fine; links decide the rest
            if (Verdict::ORDER[$lr['verdict']] > Verdict::ORDER[$verdict]) $verdict = $lr['verdict'];
            $score = max($score, $lr['risk_score']);
            if (in_array($lr['verdict'], ['malicious', 'suspicious'], true)) $reasons[] = "الرابط {$lr['url_defanged']} نتيجته: {$lr['verdict']}";
            $caveats = array_merge($caveats, $lr['caveats']);
        }
        if ($verdict === 'safe') foreach ($linkRes as $lr) if ($lr['verdict'] === 'unknown') { $verdict = 'unknown'; break; }
        if ($verdict === 'malicious') $score = max($score, 80);
        $out = ['verdict' => $verdict, 'risk_score' => (int)$score, 'action' => Verdict::ACTIONS[$verdict],
            'confidence' => in_array($verdict, ['malicious', 'suspicious'], true) ? 'normal' : $own->confidence,
            'reasons' => array_slice(array_values(array_unique($reasons)), 0, 12), 'caveats' => array_slice(array_values(array_unique($caveats)), 0, 8),
            'evidence' => ['engine' => array_map(fn($e) => $e->toArray(), $engs)],
            'links' => array_map(fn($lr) => ['url_defanged' => $lr['url_defanged'], 'verdict' => $lr['verdict'], 'risk_score' => $lr['risk_score'], 'action' => $lr['action'], 'reasons' => array_slice($lr['reasons'], 0, 4)], $linkRes)];
        return array_merge($out, $extra);
    }

    // ------------------------------------------------------------ email helpers
    /** @return array{0:string,1:string} display name, address */
    public static function parseAddr(string $v): array
    {
        if (preg_match('/^(.*?)<([^<>]*)>/s', $v, $m)) return [trim(trim($m[1]), "\" \t"), trim($m[2])];
        return ['', trim($v)];
    }

    public static function domainOf(string $addr): string
    {
        $real = self::parseAddr($addr)[1] ?: $addr;
        return preg_match('/@([\w.-]+)/', $real, $m) ? rtrim(strtolower($m[1]), '.') : '';
    }

    public static function headerChecks(array $headers): array
    {
        $first = fn(string $n) => (string)($headers[$n][0] ?? '');
        $auth = strtolower(implode(' ', $headers['authentication-results'] ?? []));
        $res = function (string $name) use ($auth) {
            return preg_match('/' . $name . '=(pass|fail|softfail|neutral|none|temperror|permerror)/', $auth, $m) ? $m[1] : 'unknown';
        };
        $frm = $first('from'); $reply = $first('reply-to'); $ret = $first('return-path');
        $display = self::parseAddr($frm)[0];
        $fromDomain = self::domainOf($frm);
        $spoof = preg_match('/[\w.+-]+@[\w-]+\.[\w.-]+/', $display) && strtolower((string)preg_replace('/.*@/', '', $display)) !== $fromDomain;
        return [
            'from' => mb_substr($frm, 0, 200), 'subject' => mb_substr($first('subject'), 0, 300), 'reply_to' => mb_substr($reply, 0, 200),
            'spf' => $res('spf'), 'dkim' => $res('dkim'), 'dmarc' => $res('dmarc'),
            'from_domain' => $fromDomain, 'reply_to_domain' => self::domainOf($reply), 'return_path_domain' => self::domainOf($ret),
            'display_name_has_other_address' => (bool)$spoof, 'received_hops' => count($headers['received'] ?? []),
        ];
    }

    public static function headerFindings(array $h): array
    {
        $f = [];
        $add = function (string $rule, string $detail, int $w) use (&$f) { $f[] = ['rule' => $rule, 'detail' => $detail, 'weight' => $w]; };
        if (in_array($h['spf'], ['fail', 'softfail'], true)) $add('SPF_FAIL', "فحص SPF فشل ({$h['spf']}): المرسل مش مصرح له يبعت باسم الدومين", 35);
        if ($h['dkim'] === 'fail') $add('DKIM_FAIL', 'توقيع DKIM فشل: الرسالة اتغيرت أو مش من المصدر', 35);
        if ($h['dmarc'] === 'fail') $add('DMARC_FAIL', 'فحص DMARC فشل', 45);
        if ($h['reply_to_domain'] && $h['from_domain'] && $h['reply_to_domain'] !== $h['from_domain']) $add('REPLY_TO_MISMATCH', "الرد بيروح لدومين مختلف ({$h['reply_to_domain']})", 40);
        if ($h['return_path_domain'] && $h['from_domain'] && $h['return_path_domain'] !== $h['from_domain']) $add('RETURN_PATH_MISMATCH', 'عنوان الإرجاع مختلف عن المرسل الظاهر', 15);
        if ($h['display_name_has_other_address']) $add('DISPLAY_NAME_SPOOF', 'الاسم المعروض فيه إيميل تاني مختلف (تقليد)', 40);
        return $f;
    }

    /** @return array{0:string,1:array,2:bool} text, http links from HTML, link text mismatch */
    public static function bodyContent(array $root): array
    {
        $texts = []; $links = []; $mismatch = false;
        foreach (Mime::leaves($root) as $p) {
            if ($p['disposition'] === 'attachment') continue;
            if ($p['type'] === 'text/plain') $texts[] = $p['body'];
            elseif ($p['type'] === 'text/html') {
                $html = mb_substr($p['body'], 0, 400000);
                if (preg_match_all('/<a\b([^>]*)>(.*?)<\/a>/is', $html, $ms, PREG_SET_ORDER)) {
                    foreach (array_slice($ms, 0, 500) as $m) {
                        if (!preg_match('/\bhref\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s>]+))/i', $m[1], $hm)) continue;
                        $href = html_entity_decode($hm[1] !== '' ? $hm[1] : ($hm[2] ?? '') . ($hm[3] ?? ''));
                        if (!preg_match('#^https?://#i', $href)) continue;
                        $links[] = $href;
                        $shown = trim(html_entity_decode(strip_tags($m[2])));
                        $isLike = preg_match('#^(https?://|www\.)#i', $shown) || preg_match('/^[a-z0-9.-]+\.[a-z]{2,24}(\/\S*)?$/i', $shown);
                        if ($isLike && preg_match('#(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,24})#i', $shown, $sm)) {
                            $sh = strtolower($sm[1]);
                            $real = U::hostOf($href);
                            if ($real !== '' && $sh !== $real && !str_ends_with($real, '.' . $sh)) $mismatch = true;
                        }
                    }
                }
                $clean = preg_replace('#<(script|style)\b.*?</\1>#is', ' ', $html) ?? $html;
                $texts[] = trim(html_entity_decode(strip_tags($clean)));
            }
        }
        return [mb_substr(implode("\n", $texts), 0, 50000), $links, $mismatch];
    }

    public static function attachmentMeta(array $root): array
    {
        $out = [];
        foreach (Mime::leaves($root) as $p) {
            if ($p['disposition'] !== 'attachment' && $p['filename'] === '') continue;
            $name = mb_substr($p['filename'] ?: 'unnamed', 0, 150);
            $data = Mime::decode($p['body'], '');
            $segs = explode('.', strtolower($name));
            $ext = count($segs) > 1 ? end($segs) : '';
            $double = count($segs) > 2 && in_array($segs[count($segs) - 2], self::DOC_EXT, true) && in_array($ext, self::RISKY_EXT, true);
            $out[] = ['filename' => $name, 'content_type' => $p['type'], 'size' => strlen($data), 'sha256' => hash('sha256', $data),
                'risky' => in_array($ext, self::RISKY_EXT, true) || $double, 'double_extension' => $double];
        }
        return array_slice($out, 0, 50);
    }
}
