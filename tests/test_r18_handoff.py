"""Round 18: fields the Risk Engine (Person 3) and history owner (Person 1) rely on."""
import asyncio
import httpx
from scanner_p2.api import create_app
from scanner_p2.enrich import severity
from helpers import scanner, settings


async def run(path, body):
    app = create_app(settings(), scanner=scanner())
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        r = await c.post(path, json=body)
        sid = r.json()["scan_id"]
        for _ in range(60):
            j = (await c.get(f"/v1/scans/{sid}")).json()
            if j["status"] in ("completed", "failed"):
                return j
            await asyncio.sleep(0.05)


def test_severity_mapping():
    assert severity("safe", 0) == "none" and severity("unknown", 0) == "unknown"
    assert severity("suspicious", 20) == "low" and severity("suspicious", 50) == "medium"
    assert severity("malicious", 40) == "high" and severity("malicious", 95) == "critical"


async def test_url_result_has_handoff_fields_and_client_ref():
    j = await run("/v1/urls/scan", {"url": "https://example.com/", "client_ref": "scan-42"})
    r = j["result"]
    assert r["client_ref"] == "scan-42" and r["scanner_verdict"] == r["verdict"] and r["severity"] in ("none", "unknown")
    assert any(i["type"] == "model_result" for i in r["evidence_items"])


async def test_failed_unknown_never_safe_severity():
    j = await run("/v1/urls/scan", {"url": "ftp://x.com/a"})
    assert j["result"]["verdict"] == "unknown" and j["result"]["severity"] == "unknown"


async def test_sms_and_protection_fields():
    j = await run("/v1/sms/scan", {"body": "اضغط http://x.top/login", "client_ref": "r1"})
    assert j["result"]["client_ref"] == "r1" and "evidence_items" in j["result"]
    app = create_app(settings(), scanner=scanner())
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        r = (await c.post("/v1/protection/sms", json={"body": "hello", "message_id": "m9"})).json()
    assert r["message_id"] == "m9" and "severity" in r and "evidence_items" in r
