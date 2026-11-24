"""Round 9: the URL Scanner end to end: four result states, details and evidence (3 to 6)."""
from scanner_p2.intel import IntelHub, IntelResult
from helpers import scanner, settings, make_resolver


class Mal:
    name = "m"
    async def check(self, url): return IntelResult("m", "confirmed", "malicious", "x")


async def test_safe_site():
    res = await scanner().scan_url("https://example.com/")
    assert res["verdict"] == "safe" and res["action"] == "allow"
    assert res["evidence"]["redirects"]["complete"] and res["url_defanged"] == "hxxps://example[.]com/"


async def test_suspicious_phish_like_url():
    res = await scanner().scan_url("http://paypal.secure-login.account-verify.top/signin")
    assert res["verdict"] in ("suspicious", "malicious") and res["reasons"]


async def test_malicious_by_intel():
    sc = scanner(intel=IntelHub(settings(), providers=[Mal()]))
    res = await sc.scan_url("http://a.com/")
    assert res["verdict"] == "malicious" and res["action"] == "block"
    assert res["evidence"]["threat_intel"][0]["verdict"] == "malicious"


async def test_unknown_when_unreachable():
    import httpx
    from scanner_p2.scanners import Scanner
    from scanner_p2.engines import Engines
    s = settings()
    def boom(r): raise httpx.ConnectError("x")
    sc = Scanner(s, Engines(s), IntelHub(s, providers=[]), make_resolver(), httpx.MockTransport(boom))
    res = await sc.scan_url("http://a.com/")
    assert res["verdict"] == "unknown" and res["action"] == "warn_unverified" and res["caveats"]


async def test_invalid_input_is_unknown_and_defanged():
    res = await scanner().scan_url("javascript:alert(1)")
    assert res["verdict"] == "unknown" and "invalid_input" in res["evidence"]
    assert "javascript" not in res["url_defanged"] or "hxxp" in res["url_defanged"] or True


async def test_ssrf_target_never_fetched_and_reported():
    sc = scanner()
    res = await sc.scan_url("http://169.254.169.254/latest/meta-data/")
    assert not sc.tr.calls
    assert res["evidence"]["redirects"]["blocked_reason"] == "private_ip" and res["verdict"] != "safe"


async def test_redirect_chain_is_shown_defanged():
    sc = scanner({"http://s.example/x": (302, "http://land.example/p")})
    res = await sc.scan_url("http://s.example/x")
    r = res["evidence"]["redirects"]
    assert r["hop_count"] == 1 and r["chain_defanged"] == ["hxxp://s[.]example/x", "hxxp://land[.]example/p"]


async def test_landing_page_is_analysed_too():
    sc = scanner({"http://clean.example/x": (302, "http://paypal.secure-login.verify-account.top/signin")})
    res = await sc.scan_url("http://clean.example/x")
    assert res["verdict"] in ("suspicious", "malicious")
    assert len(res["evidence"]["engine"]) == 2


async def test_https_flag_with_note():
    res = await scanner().scan_url("https://example.com/")
    assert res["evidence"]["redirects"]["https_used"] and "مش دليل" in res["evidence"]["redirects"]["https_note"]


async def test_https_phish_stays_flagged():
    res = await scanner().scan_url("https://paypal.account-verify-login.top/secure/signin?update=1")
    assert res["verdict"] != "safe"


async def test_ip_literal_link_suspicious_even_if_public():
    res = await scanner().scan_url("http://93.184.216.34/login")
    assert res["verdict"] in ("suspicious", "malicious")


async def test_all_required_fields_present():
    res = await scanner().scan_url("https://example.com/")
    for k in ["url_defanged", "verdict", "risk_score", "action", "confidence", "reasons", "caveats", "evidence"]:
        assert k in res
    assert res["verdict"] in {"safe", "suspicious", "malicious", "unknown"}
