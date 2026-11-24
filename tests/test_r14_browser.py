"""Round 14: Secure Browser functions (21 to 24)."""
import httpx
from scanner_p2.intel import IntelHub, IntelResult
from helpers import scanner, settings, make_resolver
from scanner_p2.api import create_app


class Mal:
    name = "m"
    async def check(self, url): return IntelResult("m", "confirmed", "malicious", "x") if "evil" in url else IntelResult("m", "inconclusive")


async def test_safe_site_opens():
    res = await scanner().browser_precheck("https://example.com/")
    assert res["browser"]["open_allowed"] and res["browser"]["interstitial"] is None


async def test_malicious_is_blocked_without_proceed_button():
    res = await scanner(intel=IntelHub(settings(), providers=[Mal()])).browser_precheck("http://evil.example/")
    b = res["browser"]
    assert not b["open_allowed"] and b["interstitial"] == "block_page" and not b["user_can_proceed"]


async def test_suspicious_gets_warning_page_user_may_proceed():
    res = await scanner().browser_precheck("http://paypal.secure-login.account-verify.top/signin")
    assert res["browser"]["interstitial"] in ("warning_page", "block_page")


async def test_redirect_to_bad_final_destination_is_caught():
    sc = scanner({"http://short.example/a": (302, "http://evil.example/x")}, intel=IntelHub(settings(), providers=[Mal()]))
    res = await sc.browser_precheck("http://short.example/a")
    assert res["verdict"] == "malicious" and res["evidence"]["redirects"]["hop_count"] == 1


async def test_redirect_into_internal_network_never_opened():
    sc = scanner({"http://short.example/a": (302, "http://192.168.0.1/router")})
    res = await sc.browser_precheck("http://short.example/a")
    assert res["verdict"] != "safe" and not res["browser"]["open_allowed"]
    assert not any("192.168" in c for c in sc.tr.calls)


async def test_https_valid_cert_phish_still_warned():
    res = await scanner().browser_precheck("https://paypal.verify-account-login.top/secure/signin")
    assert not res["browser"]["open_allowed"]


async def test_unreachable_is_unverified_notice():
    import httpx as hx
    from scanner_p2.scanners import Scanner
    from scanner_p2.engines import Engines
    s = settings()
    def boom(r): raise hx.ConnectError("x")
    sc = Scanner(s, Engines(s), IntelHub(s, providers=[]), make_resolver(), hx.MockTransport(boom))
    res = await sc.browser_precheck("http://fine.example/")
    assert res["browser"]["interstitial"] == "unverified_notice" and not res["browser"]["open_allowed"]


async def test_endpoint_works_and_deadline_fallback():
    import asyncio
    sc = scanner(browser_deadline=0.2)
    async def slow(u):
        await asyncio.sleep(2)
    sc.scan_url = slow
    app = create_app(settings(browser_deadline=0.2), scanner=sc)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        j = (await c.post("/v1/browser/precheck", json={"url": "http://a.com/"})).json()
    assert j["verdict"] == "unknown" and not j["browser"]["open_allowed"]
