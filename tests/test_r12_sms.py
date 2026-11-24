"""Round 12: SMS scanning, links coordinated with the URL scanner, reasons shown (4 to 7)."""
from scanner_p2.intel import IntelHub, IntelResult
from helpers import scanner, settings


class Mal:
    name = "m"
    async def check(self, url): return IntelResult("m", "confirmed", "malicious", "x") if "evil" in url else IntelResult("m", "inconclusive")


async def test_phishing_arabic_sms():
    res = await scanner().scan_sms("عاجل: تم إيقاف حسابك البنكي، اضغط https://nbe-verify.top/login خلال 24 ساعة", "+201001234567")
    assert res["verdict"] in ("suspicious", "malicious") and res["reasons"] and res["links"]


async def test_normal_sms_without_link_is_safe_limited():
    res = await scanner().scan_sms("هنتقابل الساعة 5 في الكافيه", "Mom")
    assert res["verdict"] == "safe" and res["confidence"] == "limited"


async def test_link_verdict_escalates_message():
    sc = scanner(intel=IntelHub(settings(), providers=[Mal()]))
    res = await sc.scan_sms("check this http://evil.example/offer")
    assert res["verdict"] == "malicious" and res["links"][0]["verdict"] == "malicious"


async def test_reasons_mention_the_bad_link():
    sc = scanner(intel=IntelHub(settings(), providers=[Mal()]))
    res = await sc.scan_sms("see http://evil.example/x")
    assert any("hxxp://evil[.]example" in r for r in res["reasons"])


async def test_link_to_internal_address_is_not_fetched():
    sc = scanner()
    res = await sc.scan_sms("open http://10.0.0.1/admin now")
    assert not sc.tr.calls and res["links"][0]["verdict"] != "safe"


async def test_otp_with_link():
    res = await scanner().scan_sms("كود التحقق 482913 لا تشاركه. لتأكيد العملية ادخل http://bit.ly/3xYz")
    assert res["verdict"] != "safe"


async def test_english_scam():
    res = await scanner().scan_sms("Congratulations you have won a prize! Click here http://claim-prize.top/now urgent")
    assert res["verdict"] != "safe"


async def test_unreachable_link_message_unknown_not_safe():
    import httpx
    from scanner_p2.scanners import Scanner
    from scanner_p2.engines import Engines
    from helpers import make_resolver
    s = settings()
    def boom(r): raise httpx.ConnectError("x")
    sc = Scanner(s, Engines(s), IntelHub(s, providers=[]), make_resolver(), httpx.MockTransport(boom))
    res = await sc.scan_sms("see http://fine-site.example/page")
    assert res["verdict"] == "unknown"


async def test_many_links_and_emoji_and_empty_body_ok():
    res = await scanner().scan_sms("😀" * 100 + " ".join(f"http://s{i}.example/" for i in range(20)))
    assert len(res["links"]) <= 10
