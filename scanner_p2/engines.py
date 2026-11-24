"""Engine adapters (2, 5, 10, 11). The ML engines belong to teammates. We talk to them over HTTP with a fixed
contract (see docs/INTEGRATION_AR.md). If no engine URL is set, a transparent local heuristic runs, so this
piece works on its own. If an engine fails we return state 'unavailable', never a guess of 'safe'."""
import re
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional
from urllib.parse import urlsplit

import httpx

from .config import Settings
from .urlnorm import parse_ip_literal

SUSPICIOUS_TLDS = {"zip", "mov", "top", "xyz", "click", "link", "gq", "tk", "ml", "cf", "ga", "work", "support", "country", "kim", "loan", "icu", "cyou", "rest", "bond", "sbs"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rebrand.ly", "shorturl.at", "ow.ly", "buff.ly", "tiny.cc", "rb.gy", "t.ly", "s.id", "wa.me"}
BRANDS = ("vodafone", "etisalat", "orange", "we.eg", "instapay", "fawry", "cib", "nbe", "banquemisr", "alexbank", "paypal", "apple", "icloud", "google", "microsoft", "facebook", "instagram", "whatsapp", "netflix", "amazon", "aramex", "dhl", "fedex", "binance", "telegram")
KEYWORDS = ("login", "signin", "verify", "secure", "account", "update", "confirm", "wallet", "bank", "billing", "password", "otp", "gift", "prize", "bonus", "claim", "suspend", "unlock", "recover")
SMS_WORDS_AR = ("تم إيقاف", "تم ايقاف", "حسابك", "سيتم إيقاف", "سيتم ايقاف", "اضغط", "ادخل", "كود التحقق", "رمز التحقق", "رمز OTP", "جائزة", "جايزة", "ربحت", "كسبت", "مبروك", "شحنة", "طرد", "جمارك", "بطاقتك", "فيزا", "محفظتك", "فودافون كاش", "انستاباي", "تحديث بياناتك", "تأكيد بياناتك", "خلال 24 ساعة", "فورا", "فوراً", "عاجل")
SMS_WORDS_EN = ("urgent", "verify your", "account suspended", "click here", "you have won", "congratulations", "confirm your", "unusual activity", "otp", "your parcel", "customs fee", "limited time")


@dataclass
class EngineResult:
    state: str                       # ok | unavailable
    engine: str = ""
    version: str = ""
    label: Optional[str] = None      # phishing | legit | suspicious
    score: Optional[float] = None    # 0..1 probability of phishing
    reasons: List[str] = field(default_factory=list)
    detail: str = ""

    def to_dict(self):
        return asdict(self)


def _valid(d: dict) -> Optional[EngineResult]:
    """Validate what a teammate engine returned. Anything malformed counts as unavailable."""
    try:
        score = float(d["score"])
        label = str(d.get("label", "")).lower()
        if not (0.0 <= score <= 1.0) or label not in {"phishing", "legit", "suspicious"}:
            return None
        reasons = [str(x)[:300] for x in (d.get("reasons") or [])][:10]
        return EngineResult("ok", str(d.get("engine", "remote"))[:60], str(d.get("version", ""))[:30], label, score, reasons)
    except (KeyError, TypeError, ValueError):
        return None


class RemoteEngine:
    """POST {base}/analyze/{kind} with {"content": ..., "context": {...}}. Reply: {label, score, reasons[], engine, version}."""

    def __init__(self, settings: Settings, transport=None):
        self.s, self.transport = settings, transport

    async def analyze(self, kind: str, content: str, context: dict) -> EngineResult:
        headers = {"Authorization": f"Bearer {self.s.engine_api_key}"} if self.s.engine_api_key else {}
        try:
            async with httpx.AsyncClient(timeout=self.s.engine_timeout, transport=self.transport) as c:
                r = await c.post(f"{self.s.engine_url_base}/analyze/{kind}", json={"content": content, "context": context}, headers=headers)
            if r.status_code != 200:
                return EngineResult("unavailable", "remote", detail=f"http_{r.status_code}")
            res = _valid(r.json())
            return res or EngineResult("unavailable", "remote", detail="invalid_engine_response")
        except (httpx.HTTPError, ValueError):
            return EngineResult("unavailable", "remote", detail="engine_unreachable")


class LocalEngine:
    """Rule based fallback. It is evidence, not a judge, and it says so in `engine`."""
    name, version = "p2-local-heuristics", "1.0"

    async def analyze(self, kind: str, content: str, context: dict) -> EngineResult:
        if kind == "url":
            score, reasons = url_heuristics(content, context)
        elif kind == "sms":
            score, reasons = sms_heuristics(content, context)
        else:
            score, reasons = email_heuristics(content, context)
        label = "phishing" if score >= 0.7 else "suspicious" if score >= 0.35 else "legit"
        return EngineResult("ok", self.name, self.version, label, round(min(score, 0.99), 3), reasons)


def url_heuristics(url: str, ctx: dict):
    p = urlsplit(url)
    host = (p.hostname or "").lower()
    s, r = 0.0, []

    def add(w, why):
        nonlocal s
        s += w
        r.append(why)

    if parse_ip_literal(host) is not None:
        add(0.45, "الرابط بيستخدم عنوان IP بدل اسم موقع")
    if p.username or "@" in p.netloc:
        add(0.4, "الرابط فيه @ بيخبي الوجهة الحقيقية")
    if host.startswith("xn--") or ".xn--" in host:
        add(0.3, "اسم الموقع بحروف مموهة (Punycode) ممكن يقلد موقع معروف")
    labels = host.split(".")
    tld = labels[-1] if labels else ""
    if tld in SUSPICIOUS_TLDS:
        add(0.2, f"امتداد الموقع .{tld} شائع في المواقع المشبوهة")
    if len(labels) >= 5:
        add(0.2, "عدد كبير من النطاقات الفرعية")
    base = ".".join(labels[-2:]) if len(labels) >= 2 else host
    sub = ".".join(labels[:-2])
    for b in BRANDS:
        if b in sub.replace("-", "") and b not in base:
            add(0.4, f"اسم علامة معروفة ({b}) داخل نطاق فرعي لموقع مختلف")
            break
    if host in SHORTENERS or base in SHORTENERS:
        add(0.25, "رابط مختصر بيخبي الوجهة")
    kws = [k for k in KEYWORDS if k in (host + p.path.lower())]
    if len(kws) >= 2:
        add(0.2, "كلمات حساسة في الرابط: " + "، ".join(kws[:3]))
    if host.count("-") >= 3:
        add(0.15, "شرطات كتير في اسم الموقع")
    if len(url) > 120:
        add(0.1, "رابط طويل جداً")
    if p.scheme == "http":
        add(0.05, "الرابط من غير تشفير (HTTP)")
    chain = ctx.get("redirect_chain") or []
    if len(chain) > 2:
        add(0.15, f"الرابط بيتحول {len(chain) - 1} مرات قبل الوصول للصفحة")
    final = ctx.get("final_url") or url
    if final and urlsplit(final).hostname and urlsplit(final).hostname != host and not ctx.get("same_site_redirect"):
        add(0.1, "الرابط بيوديك لموقع مختلف عن اللي ظاهر")
    # NOTE: HTTPS never lowers the score. A phishing site can have a valid certificate.
    return min(s, 0.99), r


def sms_heuristics(text: str, ctx: dict):
    s, r = 0.0, []
    low = text.lower()
    ar = [w for w in SMS_WORDS_AR if w in text]
    en = [w for w in SMS_WORDS_EN if w in low]
    if ar or en:
        k = min(len(ar) + len(en), 4)
        s += 0.15 * k
        r.append("كلمات ضغط أو احتيال: " + "، ".join((ar + en)[:4]))
    if ctx.get("has_links"):
        s += 0.2
        r.append("الرسالة فيها رابط")
        if ar or en:
            s += 0.15
    if re.search(r"\b\d{4,8}\b", text) and re.search(r"(otp|كود|رمز)", low) and ctx.get("has_links"):
        s += 0.25
        r.append("رسالة فيها كود تحقق ومعاها رابط")
    sender = ctx.get("sender") or ""
    if re.fullmatch(r"\+?\d{8,15}", sender) and (ar or en):
        s += 0.1
        r.append("المرسل رقم عادي بس الرسالة بتتكلم باسم جهة رسمية")
    return min(s, 0.99), r


def email_heuristics(text: str, ctx: dict):
    s, r = 0.0, []
    for f in ctx.get("header_findings", []):
        s += f["weight"] / 100.0
        r.append(f["detail"])
    ws, wr = sms_heuristics(text, {"has_links": ctx.get("has_links", False)})
    s += ws * 0.6
    r += wr[:2]
    if ctx.get("risky_attachments"):
        s += 0.35
        r.append("مرفق بامتداد خطير: " + "، ".join(ctx["risky_attachments"][:3]))
    if ctx.get("link_text_mismatch"):
        s += 0.3
        r.append("نص الرابط بيوري موقع والرابط الحقيقي لموقع تاني")
    return min(s, 0.99), r


class Engines:
    def __init__(self, settings: Settings, transport=None):
        self.local = LocalEngine()
        self.remote = RemoteEngine(settings, transport) if settings.engine_url_base else None

    async def analyze(self, kind: str, content: str, context: dict) -> EngineResult:
        if self.remote:
            res = await self.remote.analyze(kind, content, context)
            if res.state != "ok":
                # Never turn a failed teammate engine into 'safe'. Run local rules as extra evidence only.
                local = await self.local.analyze(kind, content, context)
                local.detail = f"remote_engine_failed:{res.detail}"
                local.state = "degraded"
                return local
            return res
        return await self.local.analyze(kind, content, context)
