"""URL, Email and SMS scanners and the Secure Browser pre-check. Everything returns plain dicts (JSON-ready)."""
import asyncio
import base64
import email
import email.policy
import hashlib
import re
from html.parser import HTMLParser
from typing import List, Optional
from urllib.parse import urlsplit

from .config import Settings
from .engines import Engines, EngineResult
from .fetcher import Trace, trace_redirects
from .intel import IntelHub
from .ssrf import system_resolver
from .urlnorm import BadUrl, defang, extract_urls, normalize_url, parse_ip_literal
from .verdict import ACTIONS, MALICIOUS, SAFE, SUSPICIOUS, UNKNOWN, Judgement, judge

ORDER = {SAFE: 0, UNKNOWN: 1, SUSPICIOUS: 2, MALICIOUS: 3}
RISKY_EXT = {"exe", "scr", "bat", "cmd", "com", "pif", "js", "jse", "vbs", "vbe", "wsf", "ps1", "msi", "jar", "apk", "lnk", "iso", "img", "dll", "hta", "docm", "xlsm", "pptm", "html", "htm", "svg", "chm", "reg", "zip", "rar", "7z", "one"}


class Scanner:
    def __init__(self, settings: Settings, engines: Optional[Engines] = None, intel: Optional[IntelHub] = None,
                 resolver=system_resolver, transport=None):
        self.s = settings
        self.engines = engines or Engines(settings)
        self.intel = intel or IntelHub(settings)
        self.resolver, self.transport = resolver, transport

    # ---------------------------------------------------------------- URL (1 to 6, 21 to 28)
    async def scan_url(self, raw_url: str, with_trace: bool = True) -> dict:
        try:
            url = normalize_url(raw_url, self.s.max_url_len)
        except BadUrl as e:
            return self._invalid(raw_url, str(e))
        trace = await trace_redirects(url, self.s, self.resolver, self.transport) if with_trace else Trace(url, [], url, complete=True)
        chain = trace.chain() or [url]
        ctx = {"redirect_chain": chain, "final_url": trace.final_url or url}
        eng = await self.engines.analyze("url", url, ctx)
        engs = [eng]
        if trace.final_url and trace.final_url != url and not trace.blocked_reason:
            engs.append(await self.engines.analyze("url", trace.final_url, ctx))  # the landing page matters too
        intel = await self.intel.lookup(list(dict.fromkeys(chain))[: self.s.max_redirects + 1])
        j = judge(engs, intel, [trace])
        return self._pack(url, j, engs, intel, trace)

    def _invalid(self, raw, why):
        shown = defang(str(raw)[:200]) if isinstance(raw, str) else ""
        return {"url_defanged": shown, "verdict": UNKNOWN, "risk_score": 0, "action": ACTIONS[UNKNOWN], "confidence": "limited",
                "reasons": ["الرابط غير صالح للفحص"], "caveats": [], "evidence": {"invalid_input": why}}

    def _pack(self, url, j: Judgement, engs, intel, trace: Trace) -> dict:
        return {
            "url_defanged": defang(url), "verdict": j.verdict, "risk_score": j.risk_score, "action": ACTIONS[j.verdict],
            "confidence": j.confidence, "reasons": j.reasons, "caveats": j.caveats,
            "evidence": {
                "engine": [e.to_dict() for e in engs],
                "threat_intel": [i.to_dict() for i in intel],
                "redirects": {
                    "chain_defanged": [defang(h) for h in trace.chain()],
                    "hop_count": max(0, len(trace.hops) - 1),
                    "final_url_defanged": defang(trace.final_url) if trace.final_url else "",
                    "complete": trace.complete, "error": trace.error, "blocked_reason": trace.blocked_reason,
                    "https_used": urlsplit(trace.final_url or url).scheme == "https",
                    "https_note": "HTTPS مش دليل إن الموقع آمن",
                },
            },
        }

    # ---------------------------------------------------------------- Secure Browser (21 to 24)
    async def browser_precheck(self, raw_url: str) -> dict:
        res = await asyncio.wait_for(self.scan_url(raw_url), timeout=self.s.browser_deadline)
        v = res["verdict"]
        res["browser"] = {
            "open_allowed": v == SAFE,
            "interstitial": {"MALICIOUS": "block_page", "SUSPICIOUS": "warning_page", "UNKNOWN": "unverified_notice", "SAFE": None}[v.upper()],
            "title": {MALICIOUS: "تحذير: موقع خطير", SUSPICIOUS: "تحذير: موقع مشبوه", UNKNOWN: "ما قدرناش نتأكد من الموقع", SAFE: ""}[v],
            "user_can_proceed": v in (SUSPICIOUS, UNKNOWN),   # a malicious site has no "continue anyway" button
        }
        return res

    # ---------------------------------------------------------------- SMS (4 to 7 and automatic protection)
    async def scan_sms(self, body: str, sender: str = "") -> dict:
        body = (body or "")[: self.s.max_sms_len]
        links = extract_urls(body, self.s.max_links_per_item)
        eng = await self.engines.analyze("sms", body, {"has_links": bool(links), "sender": sender})
        link_res = await self._scan_links(links)
        return self._combine("sms", [eng], link_res, {"link_count": len(links)})

    # ---------------------------------------------------------------- Email (7 to 12)
    async def scan_email(self, raw: bytes) -> dict:
        if len(raw) > self.s.max_email_bytes:
            return {"verdict": UNKNOWN, "risk_score": 0, "action": ACTIONS[UNKNOWN], "confidence": "limited",
                    "reasons": ["الإيميل أكبر من الحد المسموح"], "caveats": [], "evidence": {"too_large": True}}
        try:
            msg = email.message_from_bytes(raw, policy=email.policy.default)
        except Exception:
            return {"verdict": UNKNOWN, "risk_score": 0, "action": ACTIONS[UNKNOWN], "confidence": "limited",
                    "reasons": ["ما قدرناش نقرا الإيميل"], "caveats": [], "evidence": {"parse_error": True}}
        headers = header_checks(msg)
        findings = header_findings(headers)
        text, html_links, mismatch = body_content(msg)
        attachments = attachment_meta(msg)  # metadata only: never decoded to disk, never opened or run
        risky = [a["filename"] for a in attachments if a["risky"]]
        links = list(dict.fromkeys(extract_urls(text, self.s.max_links_per_item) + html_links))[: self.s.max_links_per_item]
        ctx = {"header_findings": findings, "has_links": bool(links), "risky_attachments": risky, "link_text_mismatch": mismatch}
        eng = await self.engines.analyze("email", (headers.get("subject", "") + "\n" + text)[:20000], ctx)
        link_res = await self._scan_links(links)
        res = self._combine("email", [eng], link_res, {"link_count": len(links)}, findings)
        res["headers"] = {k: v for k, v in headers.items() if k != "received_chain"}
        res["attachments"] = attachments
        res["attachment_note"] = "المرفقات بتتفحص كبيانات بس (الاسم والنوع والحجم والبصمة)، ومبتتفتحش ولا بتتشغل"
        if risky:
            res["reasons"].append("فيه مرفقات بامتدادات خطيرة، متفتحهاش")
            if ORDER[res["verdict"]] < ORDER[SUSPICIOUS]:
                res["verdict"], res["action"] = SUSPICIOUS, ACTIONS[SUSPICIOUS]
                res["risk_score"] = max(res["risk_score"], 40)
        return res

    # ---------------------------------------------------------------- shared
    async def _scan_links(self, links: List[str]) -> List[dict]:
        sem = asyncio.Semaphore(3)

        async def one(u):
            async with sem:
                try:
                    return await self.scan_url(u)
                except Exception:
                    return self._invalid(u, "scan_failed")
        return list(await asyncio.gather(*(one(u) for u in links)))

    def _combine(self, kind, engs: List[EngineResult], link_res: List[dict], extra: dict, findings=None) -> dict:
        own = judge(engs, [], [], findings or [])
        verdict, score = own.verdict, own.risk_score
        reasons, caveats = list(own.reasons), list(own.caveats)
        # an own verdict of 'safe' only means the text looked fine; links decide the rest
        for lr in link_res:
            if ORDER[lr["verdict"]] > ORDER[verdict]:
                verdict = lr["verdict"]
            score = max(score, lr["risk_score"])
            if lr["verdict"] in (MALICIOUS, SUSPICIOUS):
                reasons.append(f"الرابط {lr['url_defanged']} نتيجته: {lr['verdict']}")
            caveats += lr["caveats"]
        if verdict == SAFE and any(lr["verdict"] == UNKNOWN for lr in link_res):
            verdict = UNKNOWN
        if verdict == MALICIOUS:
            score = max(score, 80)
        out = {"verdict": verdict, "risk_score": int(score), "action": ACTIONS[verdict],
               "confidence": "normal" if verdict in (MALICIOUS, SUSPICIOUS) else own.confidence,
               "reasons": list(dict.fromkeys(reasons))[:12], "caveats": list(dict.fromkeys(caveats))[:8],
               "evidence": {"engine": [e.to_dict() for e in engs]},
               "links": [{"url_defanged": lr["url_defanged"], "verdict": lr["verdict"], "risk_score": lr["risk_score"],
                          "action": lr["action"], "reasons": lr["reasons"][:4]} for lr in link_res]}
        out.update(extra)
        return out


# ------------------------------------------------------------------ email helpers
def _domain(addr: str) -> str:
    """Domain of the real address (inside <>), not of a fake address typed in the display name."""
    from email.utils import parseaddr
    real = parseaddr(addr or "")[1] or addr or ""
    m = re.search(r"@([\w.-]+)", real)
    return m.group(1).lower().rstrip(".") if m else ""


def header_checks(msg) -> dict:
    auth = " ".join(str(h) for h in msg.get_all("Authentication-Results", [])).lower()

    def res(name):
        m = re.search(name + r"=(pass|fail|softfail|neutral|none|temperror|permerror)", auth)
        return m.group(1) if m else "unknown"
    frm, reply, ret = str(msg.get("From") or ""), str(msg.get("Reply-To") or ""), str(msg.get("Return-Path") or "")
    from email.utils import parseaddr
    display = parseaddr(frm)[0]
    return {
        "from": frm[:200], "subject": str(msg.get("Subject") or "")[:300], "reply_to": reply[:200],
        "spf": res("spf"), "dkim": res("dkim"), "dmarc": res("dmarc"),
        "from_domain": _domain(frm), "reply_to_domain": _domain(reply), "return_path_domain": _domain(ret),
        "display_name_has_other_address": bool(re.search(r"[\w.+-]+@[\w-]+\.[\w.-]+", display)
                                               and re.sub(r".*@", "", display).lower() != _domain(frm)),
        "received_hops": len(msg.get_all("Received", [])),
    }


def header_findings(h: dict) -> list:
    f = []

    def add(rule, detail, w):
        f.append({"rule": rule, "detail": detail, "weight": w})
    if h["spf"] in ("fail", "softfail"):
        add("SPF_FAIL", f"فحص SPF فشل ({h['spf']}): المرسل مش مصرح له يبعت باسم الدومين", 35)
    if h["dkim"] == "fail":
        add("DKIM_FAIL", "توقيع DKIM فشل: الرسالة اتغيرت أو مش من المصدر", 35)
    if h["dmarc"] == "fail":
        add("DMARC_FAIL", "فحص DMARC فشل", 45)
    if h["reply_to_domain"] and h["from_domain"] and h["reply_to_domain"] != h["from_domain"]:
        add("REPLY_TO_MISMATCH", f"الرد بيروح لدومين مختلف ({h['reply_to_domain']})", 40)
    if h["return_path_domain"] and h["from_domain"] and h["return_path_domain"] != h["from_domain"]:
        add("RETURN_PATH_MISMATCH", "عنوان الإرجاع مختلف عن المرسل الظاهر", 15)
    if h["display_name_has_other_address"]:
        add("DISPLAY_NAME_SPOOF", "الاسم المعروض فيه إيميل تاني مختلف (تقليد)", 40)
    return f


class _LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links, self.cur, self.text, self.mismatch = [], None, [], False

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self.cur = dict(attrs).get("href") or ""
            self._buf = []

    def handle_data(self, data):
        self.text.append(data)
        if self.cur is not None:
            self._buf.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self.cur is not None:
            shown = "".join(self._buf).strip()
            href = self.cur
            if href.lower().startswith(("http://", "https://")):
                self.links.append(href)
                m = re.search(r"(?i)(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,24})", shown)
                if m and shown.lower().startswith(("http", "www")) or (m and re.fullmatch(r"(?i)[a-z0-9.-]+\.[a-z]{2,24}(/\S*)?", shown)):
                    shown_host = m.group(1).lower()
                    real = (urlsplit(href).hostname or "").lower()
                    if real and shown_host != real and not real.endswith("." + shown_host):
                        self.mismatch = True
            self.cur = None


def body_content(msg):
    texts, links, mismatch = [], [], False
    for part in msg.walk():
        ct = part.get_content_type()
        if part.get_content_disposition() == "attachment":
            continue
        if ct in ("text/plain", "text/html"):
            try:
                payload = part.get_content()
            except Exception:
                continue
            if ct == "text/html":
                p = _LinkParser()
                try:
                    p.feed(payload)
                except Exception:
                    pass
                texts.append(" ".join(p.text))
                links += p.links
                mismatch = mismatch or p.mismatch
            else:
                texts.append(payload)
    return "\n".join(texts)[:50000], links, mismatch


def attachment_meta(msg) -> list:
    out = []
    for part in msg.walk():
        if part.get_content_disposition() != "attachment" and not part.get_filename():
            continue
        name = (part.get_filename() or "unnamed")[:150]
        try:
            data = part.get_payload(decode=True) or b""
        except Exception:
            data = b""
        parts = name.lower().split(".")
        ext = parts[-1] if len(parts) > 1 else ""
        double = len(parts) > 2 and parts[-2] in {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "txt"} and ext in RISKY_EXT
        out.append({"filename": name, "content_type": part.get_content_type(), "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(), "risky": ext in RISKY_EXT or double,
                    "double_extension": double})
    return out[:50]
