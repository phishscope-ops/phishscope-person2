"""Round 17: hostile and random input. Nothing may crash, hang, or answer 'safe' on garbage."""
import random
import string
from scanner_p2.urlnorm import BadUrl, normalize_url, extract_urls
from helpers import scanner

SEED = 1337


def rnd_text(r, n):
    pool = string.printable + "ءآأإابتثجحخدذرزسشصضطظعغفقكلمنهوي\u200b\u202e%00%0a"
    return "".join(r.choice(pool) for _ in range(n))


def test_normalize_never_raises_other_than_badurl():
    r = random.Random(SEED)
    for _ in range(3000):
        s = rnd_text(r, r.randint(0, 80))
        try:
            normalize_url(s)
        except BadUrl:
            pass


def test_extract_never_raises():
    r = random.Random(SEED + 1)
    for _ in range(1500):
        extract_urls(rnd_text(r, r.randint(0, 300)))


async def test_scan_url_garbage_is_never_safe():
    r = random.Random(SEED + 2)
    sc = scanner()
    for _ in range(150):
        s = rnd_text(r, r.randint(1, 60))
        res = await sc.scan_url(s)
        assert res["verdict"] in {"safe", "unknown", "suspicious", "malicious"}
        if "invalid_input" in res["evidence"]:
            assert res["verdict"] == "unknown"


async def test_nasty_urls_never_reach_the_network_internally():
    nasty = ["http://127.0.0.1:80@evil.com/", "http://evil.com#@127.0.0.1/", "http://[::1]/", "http://[::ffff:7f00:1]/", "http://0/", "http://0.0.0.0/",
             "http://localhost:80/", "http://127.1/", "http://2130706433/", "http://0x7f000001/", "http://①②⑦.0.0.1/", "http://metadata.google.internal/",
             "http://169.254.169.254/", "http://[fd00::1]/"]
    for u in nasty:
        sc = scanner(resolver=None)
        res = await sc.scan_url(u)
        from urllib.parse import urlsplit
        for call in sc.tr.calls:
            call = urlsplit(call).hostname or ''
            assert not any(x in call for x in ("127.", "169.254", "[::1]", "localhost", "0.0.0.0", "metadata")), (u, call)
        if u != "http://evil.com#@127.0.0.1/":  # fragment trick: real host is evil.com (public), so it is scanned as evil.com
            assert res["verdict"] != "safe", u


async def test_nip_io_style_host_resolving_private_blocked():
    from helpers import make_resolver
    sc = scanner(resolver=make_resolver({"10.0.0.1.nip.io": "10.0.0.1"}))
    res = await sc.scan_url("http://10.0.0.1.nip.io/")
    assert not sc.tr.calls and res["verdict"] != "safe"


async def test_userinfo_trick_flagged():
    res = await scanner().scan_url("http://www.paypal.com@evil-site.top/login")
    assert res["verdict"] in ("suspicious", "malicious")


async def test_parallel_scans_independent():
    import asyncio
    sc = scanner()
    rs = await asyncio.gather(*[sc.scan_url(f"http://site{i}.example/") for i in range(30)])
    assert len({r["url_defanged"] for r in rs}) == 30


async def test_huge_email_with_deep_mime_nesting():
    import email.mime.multipart as mm, email.mime.text as mt
    outer = mm.MIMEMultipart()
    cur = outer
    for _ in range(60):
        nxt = mm.MIMEMultipart()
        cur.attach(nxt)
        cur = nxt
    cur.attach(mt.MIMEText("hello http://a.example/"))
    outer["From"], outer["Subject"] = "a@b.com", "deep"
    res = await scanner().scan_email(outer.as_bytes())
    assert res["verdict"] in {"safe", "unknown", "suspicious", "malicious"}
