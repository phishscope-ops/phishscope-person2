"""Turns evidence into one of four results: safe, suspicious, malicious, unknown (requirement 4).
Hard rules, tested one by one:
  * HTTPS never raises trust.
  * No answer from a threat source never means safe.
  * 'safe' needs a working engine AND a finished redirect trace AND no findings. Otherwise it is 'unknown'.
"""
from dataclasses import dataclass, field
from typing import List

from .engines import EngineResult
from .fetcher import Trace
from .intel import IntelResult

SAFE, SUSPICIOUS, MALICIOUS, UNKNOWN = "safe", "suspicious", "malicious", "unknown"

ACTIONS = {MALICIOUS: "block", SUSPICIOUS: "warn", UNKNOWN: "warn_unverified", SAFE: "allow"}


@dataclass
class Judgement:
    verdict: str
    risk_score: int
    reasons: List[str] = field(default_factory=list)
    confidence: str = "limited"        # limited | normal
    caveats: List[str] = field(default_factory=list)


ERR_AR = {
    "timeout": "الموقع ما ردش في الوقت المحدد",
    "dns_failed": "اسم الموقع مش موجود أو مش بيتحل",
    "connect_error": "ما قدرناش نتصل بالموقع",
    "tls_error": "شهادة الأمان بتاعة الموقع فيها مشكلة",
    "too_many_redirects": "الرابط بيتحول مرات كتير جداً",
    "redirect_loop": "الرابط بيلف في حلقة تحويلات",
    "http_error": "حصل خطأ أثناء فتح الرابط",
    "bad_redirect_target": "التحويل بيروح لعنوان غير صالح",
}
BLOCK_AR = "الرابط بيوصل لعنوان داخلي أو خاص، اتمنع فحصه لحماية الخدمة"


def judge(engine_results: List[EngineResult], intel: List[IntelResult], traces: List[Trace], extra_findings=None) -> Judgement:
    reasons, caveats = [], []
    score = 0.0
    extra_findings = extra_findings or []

    # 1. Threat intelligence
    mal = [i for i in intel if i.state == "confirmed" and i.verdict == "malicious"]
    sus = [i for i in intel if i.state == "confirmed" and i.verdict == "suspicious"]
    for i in mal:
        reasons.append(f"مصدر تهديدات ({i.provider}) بيصنف الرابط خطير")
    for i in sus:
        reasons.append(f"مصدر تهديدات ({i.provider}) بيصنف الرابط مشبوه")
    ti_working = any(i.state in ("confirmed", "inconclusive") and i.provider != "local_blocklist" for i in intel) or \
        any(i.state == "confirmed" for i in intel)
    if intel and not ti_working:
        caveats.append("مصادر التهديدات الخارجية غير متاحة حالياً، وغيابها مش دليل إن الرابط آمن")
    if mal:
        score = max(score, 95)
    elif sus:
        score = max(score, 55)

    # 2. Engines
    ok = [e for e in engine_results if e.state == "ok"]
    bad_engine = [e for e in engine_results if e.state != "ok"]
    for e in engine_results:
        if e.state in ("ok", "degraded"):
            if e.score is not None:
                score = max(score, round(e.score * 100) if e.label != "legit" else score)
            reasons += e.reasons
        if e.state == "degraded":
            caveats.append("محرك التحليل الأساسي مش متاح، استخدمنا قواعد احتياطية")
        if e.state == "unavailable":
            caveats.append("محرك التحليل غير متاح")
    # engine said phishing with high score
    if any(e.state == "ok" and e.label == "phishing" and (e.score or 0) >= 0.85 for e in engine_results):
        score = max(score, 85)

    # 3. Redirects and reachability
    incomplete = False
    for t in traces:
        if t.blocked_reason:
            reasons.append(BLOCK_AR)
            score = max(score, 60)
            incomplete = True
        elif t.error:
            caveats.append(ERR_AR.get(t.error, "ما قدرناش نكمل فحص الرابط"))
            incomplete = True
            if t.error in ("redirect_loop", "too_many_redirects"):
                score = max(score, 45)
                reasons.append(ERR_AR[t.error])
        elif not t.complete:
            incomplete = True
        if t.truncated:
            caveats.append("الصفحة كبيرة وقرينا جزء منها بس")
    for f in extra_findings:
        score = max(score, f["weight"])
        reasons.append(f["detail"])

    score = int(min(100, round(score)))
    all_engines_ok = bool(ok) and not bad_engine and all(e.state == "ok" for e in engine_results)

    if mal or score >= 80:
        verdict = MALICIOUS
    elif sus or score >= 35:
        verdict = SUSPICIOUS
    elif all_engines_ok and not incomplete:
        verdict = SAFE
    else:
        verdict = UNKNOWN
    if verdict == SAFE:
        reasons.append("ما لقيناش مؤشرات خطر في الفحوصات المتاحة")
        if not ti_working:
            caveats.append("النتيجة مبنية على الفحص الذاتي فقط، ومفيش مصدر تهديدات خارجي أكد")
    if verdict == UNKNOWN and not reasons:
        reasons.append("ما قدرناش نوصل لنتيجة مؤكدة، اتعامل معاه بحذر")
    conf = "normal" if (verdict in (MALICIOUS, SUSPICIOUS) or (verdict == SAFE and ti_working)) else "limited"
    seen, uniq = set(), []
    for x in reasons:
        if x not in seen:
            seen.add(x)
            uniq.append(x)
    return Judgement(verdict, score, uniq[:12], conf, list(dict.fromkeys(caveats)))
