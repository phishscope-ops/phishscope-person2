"""Round 11: links inside email, and attachments are never opened (9, 12)."""
import base64
from email.message import EmailMessage
from helpers import scanner


def build(html=None, text="hello", attachments=()):
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = "a@b.com", "c@d.com", "s"
    m.set_content(text)
    if html:
        m.add_alternative(html, subtype="html")
    for name, data, mt, st in attachments:
        m.add_attachment(data, maintype=mt, subtype=st, filename=name)
    return m.as_bytes()


async def test_links_from_html_are_scanned():
    sc = scanner()
    res = await sc.scan_email(build(html='<a href="http://paypal.verify-account.top/login">PayPal</a>'))
    assert any("verify-account" in l["url_defanged"] for l in res["links"])


async def test_link_text_mismatch_flagged():
    res = await scanner().scan_email(build(html='<a href="http://evil.top/x">https://www.paypal.com/login</a>'))
    assert res["verdict"] != "safe"


async def test_matching_link_text_not_flagged_as_mismatch():
    res = await scanner().scan_email(build(html='<a href="https://www.example.com/a">https://www.example.com/a</a>'))
    assert not any("نص الرابط" in r for r in res["reasons"])


async def test_risky_attachment_flagged_and_not_executed():
    res = await scanner().scan_email(build(attachments=[("invoice.pdf.exe", b"MZ\x90\x00", "application", "octet-stream")]))
    a = res["attachments"][0]
    assert a["risky"] and a["double_extension"] and len(a["sha256"]) == 64
    assert res["verdict"] != "safe"


async def test_safe_attachment_metadata_only():
    res = await scanner().scan_email(build(attachments=[("photo.png", b"\x89PNG....", "image", "png")]))
    a = res["attachments"][0]
    assert not a["risky"] and a["size"] == 8 and "filename" in a


async def test_html_attachment_is_risky():
    res = await scanner().scan_email(build(attachments=[("login.html", b"<form>", "text", "html")]))
    assert res["attachments"][0]["risky"]


async def test_attachment_bytes_never_in_result():
    marker = b"SECRET_PAYLOAD_MARKER"
    res = await scanner().scan_email(build(attachments=[("a.zip", marker, "application", "zip")]))
    import json
    assert "SECRET_PAYLOAD_MARKER" not in json.dumps(res)


async def test_attachment_note_present():
    res = await scanner().scan_email(build(attachments=[("a.txt", b"x", "text", "plain")]))
    assert "مبتتفتحش" in res["attachment_note"]


async def test_many_links_capped():
    html = "".join(f'<a href="http://site{i}.example/">x</a>' for i in range(60))
    res = await scanner(max_links_per_item=5).scan_email(build(html=html))
    assert len(res["links"]) <= 5


async def test_malformed_html_does_not_crash():
    res = await scanner().scan_email(build(html="<a href=<<<>>> <a <a href='http://a.com/'>"))
    assert res["verdict"] in {"safe", "unknown", "suspicious", "malicious"}
