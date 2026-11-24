"""Round 7: threat intelligence (25 to 28). No answer never means safe."""
import httpx
from scanner_p2.intel import IntelHub, LocalBlocklist, VirusTotal, IntelResult
from helpers import settings, scanner, FakeIntel


def vt(handler, key="k"):
    s = settings(vt_api_key=key)
    return VirusTotal(s, transport=httpx.MockTransport(handler))


def body(mal=0, sus=0):
    return {"data": {"attributes": {"last_analysis_stats": {"malicious": mal, "suspicious": sus, "harmless": 60, "undetected": 10}}}}


async def test_no_key_is_unavailable():
    r = await VirusTotal(settings()).check("http://a.com/")
    assert r.state == "unavailable" and r.verdict is None


async def test_malicious_and_suspicious_and_clean():
    assert (await vt(lambda r: httpx.Response(200, json=body(mal=5))).check("http://a.com/")).verdict == "malicious"
    assert (await vt(lambda r: httpx.Response(200, json=body(mal=1))).check("http://b.com/")).verdict == "suspicious"
    clean = await vt(lambda r: httpx.Response(200, json=body())).check("http://c.com/")
    assert clean.verdict is None and clean.state == "inconclusive" and "not_a_safety_proof" in clean.detail


async def test_unknown_url_404_is_inconclusive():
    r = await vt(lambda r: httpx.Response(404)).check("http://a.com/")
    assert r.state == "inconclusive" and r.verdict is None


async def test_quota_and_server_errors_are_unavailable():
    assert (await vt(lambda r: httpx.Response(429)).check("http://a.com/")).state == "unavailable"
    assert (await vt(lambda r: httpx.Response(500)).check("http://b.com/")).state == "unavailable"


async def test_network_failure_and_garbage_are_unavailable():
    def boom(r):
        raise httpx.ConnectError("x")
    assert (await vt(boom).check("http://a.com/")).state == "unavailable"
    assert (await vt(lambda r: httpx.Response(200, json={"weird": 1})).check("http://b.com/")).state == "unavailable"
    assert (await vt(lambda r: httpx.Response(200, content=b"not json")).check("http://c.com/")).state == "unavailable"


async def test_cache_avoids_second_call():
    n = []
    p = vt(lambda r: (n.append(1), httpx.Response(200, json=body(mal=3)))[1])
    await p.check("http://a.com/"); await p.check("http://a.com/")
    assert len(n) == 1


async def test_api_key_goes_in_header_not_url():
    seen = {}
    def h(r):
        seen["url"], seen["key"] = str(r.url), r.headers.get("x-apikey")
        return httpx.Response(404)
    await vt(h, key="SECRET123").check("http://a.com/")
    assert "SECRET123" not in seen["url"] and seen["key"] == "SECRET123"


async def test_local_blocklist(tmp_path):
    f = tmp_path / "b.txt"
    f.write_text("# comment\nevil.com\nhttp://bad.org/phish\n")
    bl = LocalBlocklist(str(f))
    assert (await bl.check("http://login.evil.com/x")).verdict == "malicious"
    assert (await bl.check("http://bad.org/phish")).verdict == "malicious"
    assert (await bl.check("http://fine.com/")).verdict is None
    assert (await LocalBlocklist("").check("http://evil.com/")).state == "unavailable"


async def test_provider_exception_is_contained():
    hub = IntelHub(settings(), providers=[FakeIntel(RuntimeError("boom"))])
    out = await hub.lookup(["http://a.com/"])
    assert out[0].state == "unavailable"


async def test_every_hop_in_chain_is_checked():
    seen = []
    class P:
        name = "p"
        async def check(self, url):
            seen.append(url); return IntelResult("p", "inconclusive")
    await IntelHub(settings(), providers=[P()]).lookup(["http://a.com/", "http://b.com/"])
    assert seen == ["http://a.com/", "http://b.com/"]


async def test_malicious_middle_hop_makes_whole_scan_malicious():
    class P:
        name = "p"
        async def check(self, url):
            return IntelResult("p", "confirmed", "malicious", "x") if "mid" in url else IntelResult("p", "inconclusive")
    sc = scanner({"http://a.com/s": (302, "http://mid.com/x"), "http://mid.com/x": (302, "http://clean.com/")}, intel=IntelHub(settings(), providers=[P()]))
    res = await sc.scan_url("http://a.com/s")
    assert res["verdict"] == "malicious"
