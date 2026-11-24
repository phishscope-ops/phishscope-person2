"""Round 15: talking to the teammate's ML engine, and what happens when it misbehaves (2, 5, 10)."""
import httpx
from scanner_p2.engines import Engines, RemoteEngine
from scanner_p2.intel import IntelHub
from scanner_p2.scanners import Scanner
from helpers import settings, make_resolver, site


def remote(handler, **kw):
    s = settings(engine_url_base="http://engine.local", **kw)
    return s, Engines(s, transport=httpx.MockTransport(handler))


async def test_valid_reply_used():
    s, e = remote(lambda r: httpx.Response(200, json={"label": "phishing", "score": 0.97, "reasons": ["ml says so"], "engine": "xgb", "version": "4.3"}))
    r = await e.analyze("url", "http://a.com/", {})
    assert r.state == "ok" and r.label == "phishing" and r.engine == "xgb"


async def test_request_contract():
    seen = {}
    def h(req):
        seen["path"], seen["json"], seen["auth"] = req.url.path, req.read(), req.headers.get("authorization")
        return httpx.Response(200, json={"label": "legit", "score": 0.1})
    s, e = remote(h, engine_api_key="K")
    await e.analyze("sms", "مرحبا", {"has_links": False})
    import json
    assert seen["path"] == "/analyze/sms" and json.loads(seen["json"])["content"] == "مرحبا" and seen["auth"] == "Bearer K"


async def test_bad_replies_are_rejected():
    for body in [{"label": "phishing", "score": 1.5}, {"label": "phishing", "score": -0.1}, {"label": "maybe", "score": 0.5},
                 {"score": 0.5}, {"label": "legit"}, {"label": "legit", "score": "NaN-ish"}, [], "x"]:
        s, e = remote(lambda r, b=body: httpx.Response(200, json=b))
        r = await e.analyze("url", "http://a.com/", {})
        assert r.state == "degraded", body


async def test_http_errors_timeouts_and_connect_fail_degrade():
    for h in [lambda r: httpx.Response(500), lambda r: httpx.Response(404), lambda r: httpx.Response(200, content=b"<html>")]:
        s, e = remote(h)
        assert (await e.analyze("url", "http://a.com/", {})).state == "degraded"
    def boom(r): raise httpx.ConnectError("down")
    s, e = remote(boom)
    r = await e.analyze("url", "http://a.com/", {})
    assert r.state == "degraded" and "remote_engine_failed" in r.detail


async def test_engine_down_never_gives_safe_verdict():
    def boom(r): raise httpx.ConnectError("down")
    s, e = remote(boom)
    sc = Scanner(s, e, IntelHub(s, providers=[]), make_resolver(), site())
    res = await sc.scan_url("https://example.com/")
    assert res["verdict"] == "unknown" and any("محرك" in c for c in res["caveats"])


async def test_engine_down_but_local_rules_still_catch_obvious_phish():
    def boom(r): raise httpx.ConnectError("down")
    s, e = remote(boom)
    sc = Scanner(s, e, IntelHub(s, providers=[]), make_resolver(), site())
    res = await sc.scan_url("http://paypal.secure-login.account-verify.top/signin")
    assert res["verdict"] in ("suspicious", "malicious")


async def test_remote_says_legit_for_phish_looking_url_local_not_used():
    s, e = remote(lambda r: httpx.Response(200, json={"label": "legit", "score": 0.02}))
    sc = Scanner(s, e, IntelHub(s, providers=[]), make_resolver(), site())
    res = await sc.scan_url("https://example.com/")
    assert res["verdict"] == "safe"


async def test_reasons_from_engine_are_truncated():
    s, e = remote(lambda r: httpx.Response(200, json={"label": "phishing", "score": 0.9, "reasons": ["x" * 5000] * 50}))
    r = await e.analyze("url", "http://a.com/", {})
    assert len(r.reasons) == 10 and all(len(x) <= 300 for x in r.reasons)
