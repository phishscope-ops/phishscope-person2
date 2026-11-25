<?php
declare(strict_types=1);
namespace P2;

final class EngineResult
{
    public function __construct(public string $state, public string $engine = '', public string $version = '', public ?string $label = null,
                                public ?float $score = null, public array $reasons = [], public string $detail = '') {}

    public function toArray(): array
    {
        return ['state' => $this->state, 'engine' => $this->engine, 'version' => $this->version, 'label' => $this->label,
            'score' => $this->score, 'reasons' => $this->reasons, 'detail' => $this->detail];
    }
}

/**
 * Engine adapters (2, 5, 10, 11). The ML engines belong to teammates; we talk to them over HTTP with a fixed contract.
 * With no engine URL, a transparent local heuristic runs. If an engine fails we never guess "safe".
 */
class Engines
{
    const SUSPICIOUS_TLDS = ['zip','mov','top','xyz','click','link','gq','tk','ml','cf','ga','work','support','country','kim','loan','icu','cyou','rest','bond','sbs'];
    const SHORTENERS = ['bit.ly','tinyurl.com','t.co','goo.gl','is.gd','cutt.ly','rebrand.ly','shorturl.at','ow.ly','buff.ly','tiny.cc','rb.gy','t.ly','s.id','wa.me'];
    const BRANDS = ['vodafone','etisalat','orange','we.eg','instapay','fawry','cib','nbe','banquemisr','alexbank','paypal','apple','icloud','google','microsoft','facebook','instagram','whatsapp','netflix','amazon','aramex','dhl','fedex','binance','telegram'];
    const KEYWORDS = ['login','signin','verify','secure','account','update','confirm','wallet','bank','billing','password','otp','gift','prize','bonus','claim','suspend','unlock','recover'];
    const SMS_AR = ['تم إيقاف','تم ايقاف','حسابك','سيتم إيقاف','سيتم ايقاف','اضغط','ادخل','كود التحقق','رمز التحقق','رمز OTP','جائزة','جايزة','ربحت','كسبت','مبروك','شحنة','طرد','جمارك','بطاقتك','فيزا','محفظتك','فودافون كاش','انستاباي','تحديث بياناتك','تأكيد بياناتك','خلال 24 ساعة','فورا','فوراً','عاجل'];
    const SMS_EN = ['urgent','verify your','account suspended','click here','you have won','congratulations','confirm your','unusual activity','otp','your parcel','customs fee','limited time'];

    /** @var callable */
    private $post;

    /** $post(url, jsonBody, headers, timeoutSeconds): array{0:int,1:string}. Replaceable for tests. */
    public function __construct(private Config $cfg, ?callable $post = null)
    {
        $this->post = $post ?? [Http::class, 'postJson'];
    }

    public function analyze(string $kind, string $content, array $ctx): EngineResult
    {
        if ($this->cfg->engineUrlBase !== '') {
            $res = $this->remote($kind, $content, $ctx);
            if ($res->state !== 'ok') {
                // Never turn a failed teammate engine into "safe". Local rules run as extra evidence only.
                $local = $this->local($kind, $content, $ctx);
                $local->detail = 'remote_engine_failed:' . $res->detail;
                $local->state = 'degraded';
                return $local;
            }
            return $res;
        }
        return $this->local($kind, $content, $ctx);
    }

    private function remote(string $kind, string $content, array $ctx): EngineResult
    {
        $headers = $this->cfg->engineApiKey !== '' ? ['Authorization: Bearer ' . $this->cfg->engineApiKey] : [];
        try {
            $body = json_encode(['content' => $content, 'context' => (object)$ctx], JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
            [$code, $raw] = ($this->post)($this->cfg->engineUrlBase . '/analyze/' . $kind, (string)$body, $headers, $this->cfg->engineTimeout);
        } catch (\Throwable) {
            return new EngineResult('unavailable', 'remote', detail: 'engine_unreachable');
        }
        if ($code !== 200) return new EngineResult('unavailable', 'remote', detail: "http_$code");
        $res = self::valid(json_decode($raw, true));
        return $res ?? new EngineResult('unavailable', 'remote', detail: 'invalid_engine_response');
    }

    /** Validate what a teammate engine returned. Anything malformed counts as unavailable. */
    public static function valid(mixed $d): ?EngineResult
    {
        if (!is_array($d) || !isset($d['score']) || !(is_int($d['score']) || is_float($d['score']))) return null;
        $score = (float)$d['score'];
        $label = strtolower((string)($d['label'] ?? ''));
        if ($score < 0.0 || $score > 1.0 || is_nan($score) || !in_array($label, ['phishing', 'legit', 'suspicious'], true)) return null;
        $reasons = [];
        foreach (array_slice(is_array($d['reasons'] ?? null) ? $d['reasons'] : [], 0, 10) as $r) $reasons[] = mb_substr((string)(is_scalar($r) ? $r : ''), 0, 300);
        return new EngineResult('ok', mb_substr((string)($d['engine'] ?? 'remote'), 0, 60), mb_substr((string)($d['version'] ?? ''), 0, 30), $label, $score, $reasons);
    }

    public function local(string $kind, string $content, array $ctx): EngineResult
    {
        [$score, $reasons] = match ($kind) {
            'url' => self::urlHeuristics($content, $ctx),
            'sms' => self::smsHeuristics($content, $ctx),
            default => self::emailHeuristics($content, $ctx),
        };
        $label = $score >= 0.7 ? 'phishing' : ($score >= 0.35 ? 'suspicious' : 'legit');
        return new EngineResult('ok', 'p2-local-heuristics', '1.0', $label, round(min($score, 0.99), 3), $reasons);
    }

    public static function urlHeuristics(string $url, array $ctx): array
    {
        $host = U::hostOf($url);
        $path = strtolower(U::pathOf($url));
        $s = 0.0; $r = [];
        $add = function (float $w, string $why) use (&$s, &$r) { $s += $w; $r[] = $why; };
        if (U::parseIpLiteral($host) !== null) $add(0.45, 'الرابط بيستخدم عنوان IP بدل اسم موقع');
        if (U::hasUserinfo($url)) $add(0.4, 'الرابط فيه @ بيخبي الوجهة الحقيقية');
        if (str_starts_with($host, 'xn--') || strpos($host, '.xn--') !== false) $add(0.3, 'اسم الموقع بحروف مموهة (Punycode) ممكن يقلد موقع معروف');
        $labels = explode('.', $host);
        $tld = end($labels);
        if (in_array($tld, self::SUSPICIOUS_TLDS, true)) $add(0.2, "امتداد الموقع .$tld شائع في المواقع المشبوهة");
        if (count($labels) >= 5) $add(0.2, 'عدد كبير من النطاقات الفرعية');
        $base = count($labels) >= 2 ? implode('.', array_slice($labels, -2)) : $host;
        $sub = implode('.', array_slice($labels, 0, max(0, count($labels) - 2)));
        foreach (self::BRANDS as $b) {
            if (strpos(str_replace('-', '', $sub), $b) !== false && strpos($base, $b) === false) {
                $add(0.4, "اسم علامة معروفة ($b) داخل نطاق فرعي لموقع مختلف");
                break;
            }
        }
        if (in_array($host, self::SHORTENERS, true) || in_array($base, self::SHORTENERS, true)) $add(0.25, 'رابط مختصر بيخبي الوجهة');
        $kws = array_values(array_filter(self::KEYWORDS, fn($k) => strpos($host . $path, $k) !== false));
        if (count($kws) >= 2) $add(0.2, 'كلمات حساسة في الرابط: ' . implode('، ', array_slice($kws, 0, 3)));
        if (substr_count($host, '-') >= 3) $add(0.15, 'شرطات كتير في اسم الموقع');
        if (strlen($url) > 120) $add(0.1, 'رابط طويل جداً');
        if (U::schemeOf($url) === 'http') $add(0.05, 'الرابط من غير تشفير (HTTP)');
        $chain = $ctx['redirect_chain'] ?? [];
        if (count($chain) > 2) $add(0.15, 'الرابط بيتحول ' . (count($chain) - 1) . ' مرات قبل الوصول للصفحة');
        $final = $ctx['final_url'] ?? $url;
        if ($final && U::hostOf($final) !== '' && U::hostOf($final) !== $host && empty($ctx['same_site_redirect'])) $add(0.1, 'الرابط بيوديك لموقع مختلف عن اللي ظاهر');
        // NOTE: HTTPS never lowers the score. A phishing site can have a valid certificate.
        return [min($s, 0.99), $r];
    }

    public static function smsHeuristics(string $text, array $ctx): array
    {
        $s = 0.0; $r = [];
        $low = mb_strtolower($text);
        $ar = array_values(array_filter(self::SMS_AR, fn($w) => strpos($text, $w) !== false));
        $en = array_values(array_filter(self::SMS_EN, fn($w) => strpos($low, $w) !== false));
        if ($ar || $en) {
            $k = min(count($ar) + count($en), 4);
            $s += 0.15 * $k;
            $r[] = 'كلمات ضغط أو احتيال: ' . implode('، ', array_slice(array_merge($ar, $en), 0, 4));
        }
        $links = !empty($ctx['has_links']);
        if ($links) {
            $s += 0.2; $r[] = 'الرسالة فيها رابط';
            if ($ar || $en) $s += 0.15;
        }
        if ($links && preg_match('/(?<!\d)\d{4,8}(?!\d)/', $text) && preg_match('/(otp|كود|رمز)/u', $low)) {
            $s += 0.25; $r[] = 'رسالة فيها كود تحقق ومعاها رابط';
        }
        $sender = (string)($ctx['sender'] ?? '');
        if (preg_match('/^\+?\d{8,15}$/', $sender) && ($ar || $en)) {
            $s += 0.1; $r[] = 'المرسل رقم عادي بس الرسالة بتتكلم باسم جهة رسمية';
        }
        return [min($s, 0.99), $r];
    }

    public static function emailHeuristics(string $text, array $ctx): array
    {
        $s = 0.0; $r = [];
        foreach ($ctx['header_findings'] ?? [] as $f) { $s += $f['weight'] / 100.0; $r[] = $f['detail']; }
        [$ws, $wr] = self::smsHeuristics($text, ['has_links' => $ctx['has_links'] ?? false]);
        $s += $ws * 0.6;
        $r = array_merge($r, array_slice($wr, 0, 2));
        if (!empty($ctx['risky_attachments'])) { $s += 0.35; $r[] = 'مرفق بامتداد خطير: ' . implode('، ', array_slice($ctx['risky_attachments'], 0, 3)); }
        if (!empty($ctx['link_text_mismatch'])) { $s += 0.3; $r[] = 'نص الرابط بيوري موقع والرابط الحقيقي لموقع تاني'; }
        return [min($s, 0.99), $r];
    }
}
