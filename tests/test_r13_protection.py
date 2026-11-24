"""Round 13: automatic SMS protection: speed, failures, what the app gets back (13 to 16 of the SMS items)."""
import asyncio
import httpx
from helpers import scanner, settings
from scanner_p2.api import create_app


def client(sc, **kw):
    s = settings(**kw)
    app = create_app(s, scanner=sc)
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")


async def test_normal_flow_returns_warning_fields():
    async with client(scanner()) as c:
        r = await c.post("/v1/protection/sms", json={"body": "تم إيقاف حسابك اضغط http://nbe-verify.top/login", "sender": "NBE", "message_id": "m-1"})
    j = r.json()
    assert r.status_code == 200 and j["message_id"] == "m-1" and j["status"] == "ok"
    assert j["show_warning"] is True and j["action"] in ("warn", "block")


async def test_safe_message_no_warning():
    async with client(scanner()) as c:
        j = (await c.post("/v1/protection/sms", json={"body": "see you at 5", "sender": "Ali"})).json()
    assert j["show_warning"] is False and j["verdict"] == "safe"


async def test_timeout_returns_unknown_with_warning():
    sc = scanner()
    async def slow(*a, **k):
        await asyncio.sleep(2)
    sc.scan_sms = slow
    async with client(sc, protection_deadline=0.2) as c:
        j = (await c.post("/v1/protection/sms", json={"body": "hi"})).json()
    assert j["status"] == "timeout" and j["verdict"] == "unknown" and j["show_warning"] is True


async def test_engine_crash_returns_service_unavailable_not_500():
    sc = scanner()
    async def boom(*a, **k):
        raise RuntimeError("engine exploded")
    sc.scan_sms = boom
    async with client(sc) as c:
        r = await c.post("/v1/protection/sms", json={"body": "hi"})
    j = r.json()
    assert r.status_code == 200 and j["status"] == "service_unavailable" and j["verdict"] == "unknown"


async def test_fast_for_plain_text():
    import time
    async with client(scanner()) as c:
        t0 = time.time()
        await c.post("/v1/protection/sms", json={"body": "hello there"})
    assert time.time() - t0 < 1.0


async def test_burst_of_requests_all_answered():
    async with client(scanner(), rate_limit_per_minute=1000) as c:
        rs = await asyncio.gather(*[c.post("/v1/protection/sms", json={"body": f"msg {i} http://a{i}.example/"}) for i in range(40)])
    assert all(r.status_code == 200 for r in rs)


async def test_empty_body_rejected_cleanly():
    async with client(scanner()) as c:
        assert (await c.post("/v1/protection/sms", json={"body": ""})).status_code == 422
