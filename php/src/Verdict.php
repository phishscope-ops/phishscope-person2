<?php
declare(strict_types=1);
namespace P2;

final class Judgement
{
    public function __construct(public string $verdict, public int $riskScore, public array $reasons = [], public string $confidence = 'limited', public array $caveats = []) {}
}

/**
 * Turns evidence into one of four results: safe, suspicious, malicious, unknown. Hard rules:
 *  - HTTPS never raises trust.
 *  - No answer from a threat source never means safe.
 *  - "safe" needs a working engine AND a finished redirect trace AND no findings. Otherwise it is "unknown".
 */
final class Verdict
{
    const SAFE = 'safe', SUSPICIOUS = 'suspicious', MALICIOUS = 'malicious', UNKNOWN = 'unknown';
    const ACTIONS = ['malicious' => 'block', 'suspicious' => 'warn', 'unknown' => 'warn_unverified', 'safe' => 'allow'];
    const ORDER = ['safe' => 0, 'unknown' => 1, 'suspicious' => 2, 'malicious' => 3];
    const ERR_AR = [
        'timeout' => 'الموقع ما ردش في الوقت المحدد', 'dns_failed' => 'اسم الموقع مش موجود أو مش بيتحل',
        'connect_error' => 'ما قدرناش نتصل بالموقع', 'tls_error' => 'شهادة الأمان بتاعة الموقع فيها مشكلة',
        'too_many_redirects' => 'الرابط بيتحول مرات كتير جداً', 'redirect_loop' => 'الرابط بيلف في حلقة تحويلات',
        'http_error' => 'حصل خطأ أثناء فتح الرابط', 'bad_redirect_target' => 'التحويل بيروح لعنوان غير صالح',
    ];
    const BLOCK_AR = 'الرابط بيوصل لعنوان داخلي أو خاص، اتمنع فحصه لحماية الخدمة';

    /**
     * @param EngineResult[] $engines
     * @param IntelResult[] $intel
     * @param Trace[] $traces
     */
    public static function judge(array $engines, array $intel, array $traces, array $extra = []): Judgement
    {
        $reasons = []; $caveats = []; $score = 0.0;
        $mal = array_values(array_filter($intel, fn($i) => $i->state === 'confirmed' && $i->verdict === 'malicious'));
        $sus = array_values(array_filter($intel, fn($i) => $i->state === 'confirmed' && $i->verdict === 'suspicious'));
        foreach ($mal as $i) $reasons[] = "مصدر تهديدات ({$i->provider}) بيصنف الرابط خطير";
        foreach ($sus as $i) $reasons[] = "مصدر تهديدات ({$i->provider}) بيصنف الرابط مشبوه";
        $tiWorking = false;
        foreach ($intel as $i) {
            if (($i->state === 'confirmed' || $i->state === 'inconclusive') && $i->provider !== 'local_blocklist') $tiWorking = true;
            if ($i->state === 'confirmed') $tiWorking = true;
        }
        if ($intel && !$tiWorking) $caveats[] = 'مصادر التهديدات الخارجية غير متاحة حالياً، وغيابها مش دليل إن الرابط آمن';
        if ($mal) $score = max($score, 95); elseif ($sus) $score = max($score, 55);

        $allOk = $engines !== [];
        foreach ($engines as $e) {
            if ($e->state === 'ok' || $e->state === 'degraded') {
                if ($e->score !== null) $score = max($score, $e->label !== 'legit' ? round($e->score * 100) : $score);
                $reasons = array_merge($reasons, $e->reasons);
            }
            if ($e->state === 'degraded') $caveats[] = 'محرك التحليل الأساسي مش متاح، استخدمنا قواعد احتياطية';
            if ($e->state === 'unavailable') $caveats[] = 'محرك التحليل غير متاح';
            if ($e->state !== 'ok') $allOk = false;
        }
        foreach ($engines as $e) if ($e->state === 'ok' && $e->label === 'phishing' && ($e->score ?? 0) >= 0.85) $score = max($score, 85);

        $incomplete = false;
        foreach ($traces as $t) {
            if ($t->blockedReason !== '') { $reasons[] = self::BLOCK_AR; $score = max($score, 60); $incomplete = true; }
            elseif ($t->error !== '') {
                $caveats[] = self::ERR_AR[$t->error] ?? 'ما قدرناش نكمل فحص الرابط';
                $incomplete = true;
                if (in_array($t->error, ['redirect_loop', 'too_many_redirects'], true)) { $score = max($score, 45); $reasons[] = self::ERR_AR[$t->error]; }
            } elseif (!$t->complete) $incomplete = true;
            if ($t->truncated) $caveats[] = 'الصفحة كبيرة وقرينا جزء منها بس';
        }
        foreach ($extra as $f) { $score = max($score, $f['weight']); $reasons[] = $f['detail']; }

        $score = (int)min(100, round($score));
        if ($mal || $score >= 80) $verdict = self::MALICIOUS;
        elseif ($sus || $score >= 35) $verdict = self::SUSPICIOUS;
        elseif ($allOk && !$incomplete) $verdict = self::SAFE;
        else $verdict = self::UNKNOWN;
        if ($verdict === self::SAFE) {
            $reasons[] = 'ما لقيناش مؤشرات خطر في الفحوصات المتاحة';
            if (!$tiWorking) $caveats[] = 'النتيجة مبنية على الفحص الذاتي فقط، ومفيش مصدر تهديدات خارجي أكد';
        }
        if ($verdict === self::UNKNOWN && !$reasons) $reasons[] = 'ما قدرناش نوصل لنتيجة مؤكدة، اتعامل معاه بحذر';
        $conf = ($verdict === self::MALICIOUS || $verdict === self::SUSPICIOUS || ($verdict === self::SAFE && $tiWorking)) ? 'normal' : 'limited';
        return new Judgement($verdict, $score, array_slice(array_values(array_unique($reasons)), 0, 12), $conf, array_values(array_unique($caveats)));
    }
}
