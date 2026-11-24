"""HTTP API. Version 1. See docs/INTEGRATION_AR.md for the contract each teammate uses."""
import asyncio
import base64
import binascii
import hmac
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from . import __version__
from .config import Settings, get_settings
from .logsafe import get_logger
from .ratelimit import RateLimiter
from .scanners import Scanner
from .store import ScanStore
from .urlnorm import defang
from .verdict import ACTIONS, UNKNOWN

log = get_logger()


class UrlIn(BaseModel):
    url: str = Field(min_length=1, max_length=4096)


class SmsIn(BaseModel):
    body: str = Field(min_length=1, max_length=20000)
    sender: str = Field(default="", max_length=64)


class ProtectionIn(BaseModel):
    body: str = Field(min_length=1, max_length=20000)
    sender: str = Field(default="", max_length=64)
    received_at: Optional[str] = Field(default=None, max_length=40)
    message_id: Optional[str] = Field(default=None, max_length=80)  # the app's own id, echoed back


class EmailIn(BaseModel):
    eml_base64: Optional[str] = Field(default=None, max_length=14_000_000)
    eml_text: Optional[str] = Field(default=None, max_length=10_000_000)


def create_app(settings: Optional[Settings] = None, scanner: Optional[Scanner] = None, store: Optional[ScanStore] = None) -> FastAPI:
    s = settings or get_settings()
    sc = scanner or Scanner(s)
    st = store or ScanStore(s.db_path, s.scan_ttl_seconds)
    limiter = RateLimiter(s.rate_limit_per_minute)
    sem = asyncio.Semaphore(s.max_concurrent_scans)
    tasks: set = set()
    app = FastAPI(title="PhishScope Person 2 Scanner", version=__version__)

    async def guard(request: Request):
        if s.api_key:
            given = request.headers.get("x-api-key", "")
            if not hmac.compare_digest(given.encode(), s.api_key.encode()):
                raise HTTPException(401, {"error": "unauthorized"})
        client = request.headers.get("x-api-key") or (request.client.host if request.client else "anon")
        if not limiter.allow(client):
            raise HTTPException(429, {"error": "rate_limited"}, headers={"Retry-After": "30"})

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception):
        log.error("unhandled %s on %s", type(exc).__name__, request.url.path)  # never log the body
        return JSONResponse({"error": "internal_error", "verdict": UNKNOWN, "action": ACTIONS[UNKNOWN]}, status_code=500)

    @app.get("/health")
    async def health():
        return {"status": "ok", "version": __version__, "engine": "remote" if s.engine_url_base else "local-heuristics",
                "threat_intel": {"virustotal": bool(s.vt_api_key), "local_blocklist": bool(s.blocklist_file)}}

    async def run_job(sid: str, coro_factory):
        async with sem:
            st.update(sid, "running")
            try:
                result = await asyncio.wait_for(coro_factory(), timeout=s.fetch_total_deadline * 3 + 30)
                st.update(sid, "completed", result)
            except Exception as e:
                log.error("job failed %s", type(e).__name__)
                st.update(sid, "failed", {"verdict": UNKNOWN, "action": ACTIONS[UNKNOWN], "reasons": ["فشل التحليل"], "caveats": ["حاول تاني بعد شوية"]})

    def spawn(sid, factory):
        t = asyncio.create_task(run_job(sid, factory))
        tasks.add(t)
        t.add_done_callback(tasks.discard)

    # ---- URL Scanner: submit, then poll (requirement 3 and 6)
    @app.post("/v1/urls/scan", status_code=202, dependencies=[Depends(guard)])
    async def scan_url(body: UrlIn):
        sid = st.create("url")
        spawn(sid, lambda: sc.scan_url(body.url))
        return {"scan_id": sid, "status": "queued", "poll_url": f"/v1/scans/{sid}"}

    @app.get("/v1/scans/{scan_id}", dependencies=[Depends(guard)])
    async def get_scan(scan_id: str):
        rec = st.get(scan_id)
        if not rec:
            raise HTTPException(404, {"error": "scan_not_found"})
        return rec

    # ---- Email Scanner
    @app.post("/v1/emails/scan", status_code=202, dependencies=[Depends(guard)])
    async def scan_email(body: EmailIn):
        if body.eml_base64:
            try:
                raw = base64.b64decode(body.eml_base64, validate=True)
            except (binascii.Error, ValueError):
                raise HTTPException(422, {"error": "invalid_base64"})
        elif body.eml_text:
            raw = body.eml_text.encode("utf-8", "replace")
        else:
            raise HTTPException(422, {"error": "eml_base64_or_eml_text_required"})
        if len(raw) > s.max_email_bytes:
            raise HTTPException(413, {"error": "email_too_large", "max_bytes": s.max_email_bytes})
        sid = st.create("email")
        spawn(sid, lambda: sc.scan_email(raw))
        return {"scan_id": sid, "status": "queued", "poll_url": f"/v1/scans/{sid}"}

    # ---- SMS Scanner (manual check)
    @app.post("/v1/sms/scan", status_code=202, dependencies=[Depends(guard)])
    async def scan_sms(body: SmsIn):
        sid = st.create("sms")
        spawn(sid, lambda: sc.scan_sms(body.body, body.sender))
        return {"scan_id": sid, "status": "queued", "poll_url": f"/v1/scans/{sid}"}

    # ---- Automatic SMS Protection: one fast synchronous call per incoming message
    @app.post("/v1/protection/sms", dependencies=[Depends(guard)])
    async def protect_sms(body: ProtectionIn):
        try:
            res = await asyncio.wait_for(sc.scan_sms(body.body, body.sender), timeout=s.protection_deadline)
            status = "ok"
        except asyncio.TimeoutError:
            res = {"verdict": UNKNOWN, "risk_score": 0, "action": ACTIONS[UNKNOWN], "confidence": "limited", "links": [],
                   "reasons": ["التحليل أخد وقت أطول من المسموح"], "caveats": ["اعتبر الرسالة غير مؤكدة"], "evidence": {}}
            status = "timeout"
        except Exception as e:
            log.error("protection failed %s", type(e).__name__)
            res = {"verdict": UNKNOWN, "risk_score": 0, "action": ACTIONS[UNKNOWN], "confidence": "limited", "links": [],
                   "reasons": ["الخدمة مش متاحة حالياً"], "caveats": ["اعتبر الرسالة غير مؤكدة"], "evidence": {}}
            status = "service_unavailable"
        return {"message_id": body.message_id, "status": status, "show_warning": res["verdict"] != "safe", **res}

    # ---- Secure Browser pre-check
    @app.post("/v1/browser/precheck", dependencies=[Depends(guard)])
    async def precheck(body: UrlIn):
        try:
            return await sc.browser_precheck(body.url)
        except asyncio.TimeoutError:
            return {"url_defanged": defang(body.url[:200]), "verdict": UNKNOWN, "risk_score": 0, "action": ACTIONS[UNKNOWN],
                    "confidence": "limited", "reasons": ["الفحص أخد وقت أطول من المسموح"], "caveats": [],
                    "browser": {"open_allowed": False, "interstitial": "unverified_notice", "title": "ما قدرناش نتأكد من الموقع", "user_can_proceed": True},
                    "evidence": {}}

    return app


def app_factory():
    return create_app()
