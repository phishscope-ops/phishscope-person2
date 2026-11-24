"""Round 16: the HTTP contract the team relies on, plus log safety (3, 6 and security 11)."""
import asyncio
import base64
import logging
import httpx
from scanner_p2.api import create_app
from scanner_p2.logsafe import scrub, get_logger
from helpers import scanner, settings


def client(**kw):
    s = settings(**kw)
    app = create_app(s, scanner=scanner())
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")


async def poll(c, sid, headers=None):
    for _ in range(50):
        j = (await c.get(f"/v1/scans/{sid}", headers=headers or {})).json()
        if j["status"] in ("completed", "failed"):
            return j
        await asyncio.sleep(0.05)
    raise AssertionError("never finished")


async def test_submit_then_poll_url():
    async with client() as c:
        r = await c.post("/v1/urls/scan", json={"url": "https://example.com/"})
        assert r.status_code == 202 and r.json()["status"] == "queued"
        j = await poll(c, r.json()["scan_id"])
    assert j["status"] == "completed" and j["result"]["verdict"] == "safe" and j["kind"] == "url"


async def test_unknown_scan_id_404():
    async with client() as c:
        assert (await c.get("/v1/scans/does-not-exist")).status_code == 404


async def test_email_scan_both_input_forms():
    raw = b"From: a@b.com\r\nSubject: x\r\nContent-Type: text/plain\r\n\r\nhello\r\n"
    async with client() as c:
        a = await c.post("/v1/emails/scan", json={"eml_base64": base64.b64encode(raw).decode()})
        b = await c.post("/v1/emails/scan", json={"eml_text": raw.decode()})
        assert a.status_code == b.status_code == 202
        assert (await poll(c, a.json()["scan_id"]))["result"]["headers"]["from"]


async def test_email_bad_inputs():
    async with client() as c:
        assert (await c.post("/v1/emails/scan", json={})).status_code == 422
        assert (await c.post("/v1/emails/scan", json={"eml_base64": "***not base64***"})).status_code == 422


async def test_email_too_large_413():
    async with client(max_email_bytes=50) as c:
        assert (await c.post("/v1/emails/scan", json={"eml_text": "x" * 500})).status_code == 413


async def test_sms_scan_flow():
    async with client() as c:
        r = await c.post("/v1/sms/scan", json={"body": "اضغط http://a.example/x", "sender": "X"})
        j = await poll(c, r.json()["scan_id"])
    assert j["result"]["verdict"] in {"safe", "unknown", "suspicious", "malicious"}


async def test_api_key_required_when_set():
    async with client(api_key="s3cret") as c:
        assert (await c.post("/v1/urls/scan", json={"url": "http://a.com"})).status_code == 401
        assert (await c.post("/v1/urls/scan", json={"url": "http://a.com"}, headers={"x-api-key": "wrong"})).status_code == 401
        assert (await c.post("/v1/urls/scan", json={"url": "http://a.com"}, headers={"x-api-key": "s3cret"})).status_code == 202
        assert (await c.get("/health")).status_code == 200


async def test_rate_limit_429():
    async with client(rate_limit_per_minute=3) as c:
        codes = [(await c.post("/v1/browser/precheck", json={"url": "http://a.com"})).status_code for _ in range(5)]
    assert codes.count(429) == 2


async def test_validation_errors_are_422_not_500():
    async with client() as c:
        for path, body in [("/v1/urls/scan", {}), ("/v1/urls/scan", {"url": ""}), ("/v1/sms/scan", {"body": ""}), ("/v1/browser/precheck", {"url": 5})]:
            assert (await c.post(path, json=body)).status_code == 422


async def test_health_reports_mode_without_secrets():
    async with client(vt_api_key="SUPERSECRETKEY") as c:
        j = (await c.get("/health")).json()
    assert "SUPERSECRETKEY" not in str(j) and j["threat_intel"]["virustotal"] is True


async def test_failed_job_reports_unknown_not_safe():
    sc = scanner()
    async def boom(u): raise RuntimeError("x")
    sc.scan_url = boom
    app = create_app(settings(), scanner=sc)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        r = await c.post("/v1/urls/scan", json={"url": "http://a.com"})
        j = await poll(c, r.json()["scan_id"])
    assert j["status"] == "failed" and j["result"]["verdict"] == "unknown"


def test_scrub_masks_sensitive_things():
    for raw in ["x-apikey: ABCDEF123456", "Authorization: Bearer abcdefghijklmnop12345", "mail ali@example.com now", "call +201001234567",
                "GET /a?token=123&x=1", "key=" + "A" * 40]:
        out = scrub(raw)
        assert "ABCDEF123456" not in out and "abcdefghijklmnop12345" not in out and "ali@example.com" not in out
        assert "+201001234567" not in out and "token=123" not in out and "A" * 40 not in out


async def test_scan_logs_never_contain_message_text(caplog):
    log = get_logger()
    sc = scanner()
    async def boom(*a, **k): raise RuntimeError("body was: كلمة سر 123456 اتصل 01001234567")
    sc.scan_sms = boom
    app = create_app(settings(), scanner=sc)
    with caplog.at_level(logging.DEBUG, logger="scanner_p2"):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
            await c.post("/v1/protection/sms", json={"body": "كلمة سر 123456 اتصل 01001234567 http://a.example/?token=zzz"})
    text = " ".join(r.getMessage() for r in caplog.records)
    assert "كلمة سر" not in text and "01001234567" not in text and "token=zzz" not in text
