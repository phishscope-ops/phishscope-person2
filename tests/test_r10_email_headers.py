"""Round 10: email headers and authentication (8, 9, 10, 11)."""
from helpers import scanner


def eml(headers="", body="Hello", ctype="text/plain"):
    return (f"From: Bank <support@bank.com>\r\nTo: me@x.org\r\nSubject: Hi\r\n{headers}MIME-Version: 1.0\r\nContent-Type: {ctype}; charset=utf-8\r\n\r\n{body}\r\n").encode()


async def test_clean_email():
    res = await scanner().scan_email(eml("Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\r\n"))
    assert res["verdict"] == "safe" and res["headers"]["spf"] == "pass"


async def test_spf_dkim_dmarc_fail_is_flagged():
    res = await scanner().scan_email(eml("Authentication-Results: mx; spf=fail; dkim=fail; dmarc=fail\r\n"))
    assert res["verdict"] in ("suspicious", "malicious")
    assert any("DMARC" in r or "SPF" in r for r in res["reasons"])


async def test_reply_to_mismatch():
    res = await scanner().scan_email(eml("Reply-To: help@evil-mail.top\r\nAuthentication-Results: mx; spf=pass; dkim=pass\r\n"))
    assert res["headers"]["reply_to_domain"] == "evil-mail.top" and res["verdict"] == "suspicious"


async def test_display_name_spoof():
    raw = b"From: \"support@paypal.com\" <x@evil.top>\r\nSubject: s\r\nContent-Type: text/plain\r\n\r\nhi\r\n"
    res = await scanner().scan_email(raw)
    assert res["headers"]["display_name_has_other_address"] and res["verdict"] != "safe"


async def test_missing_auth_headers_is_not_proof_of_safe_or_bad():
    res = await scanner().scan_email(eml())
    assert res["headers"]["spf"] == "unknown"


async def test_garbage_input_does_not_crash():
    for raw in [b"", b"\x00\xff\xfe" * 50, b"not an email at all", b"From:", b"\r\n\r\n"]:
        res = await scanner().scan_email(raw)
        assert res["verdict"] in {"safe", "unknown", "suspicious", "malicious"}


async def test_too_large_email_unknown():
    res = await scanner(max_email_bytes=100).scan_email(b"x" * 500)
    assert res["verdict"] == "unknown"


async def test_arabic_subject_and_body():
    raw = "From: a@b.com\r\nSubject: =?utf-8?B?2KrYrdiw2YrYsSDYudin2KzZhA==?=\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nتم إيقاف حسابك اضغط الآن\r\n".encode()
    res = await scanner().scan_email(raw)
    assert "تحذير" in res["headers"]["subject"]
