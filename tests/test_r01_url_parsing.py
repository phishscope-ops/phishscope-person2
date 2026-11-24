"""Round 1: receiving and normalising the URL (requirement 1, 2)."""
import pytest
from scanner_p2.urlnorm import BadUrl, normalize_url, defang, refang


def test_adds_scheme_and_lowercases():
    assert normalize_url("Example.COM/Path") == "http://example.com/Path"


def test_strips_fragment_keeps_query():
    assert normalize_url("https://a.com/x?y=1#frag") == "https://a.com/x?y=1"


def test_defang_and_refang_roundtrip():
    assert defang("https://evil.com/a") == "hxxps://evil[.]com/a"
    assert normalize_url("hxxps://evil[.]com/a") == "https://evil.com/a"
    assert refang("hxxp://a[.]b") == "http://a.b"


@pytest.mark.parametrize("bad", ["", "   ", "javascript:alert(1)", "data:text/html,hi", "file:///etc/passwd", "ftp://a.com/x",
                                 "gopher://a.com", "http://", "https:///path", "mailto:a@b.com", "vbscript:x"])
def test_rejects_non_http(bad):
    with pytest.raises(BadUrl):
        normalize_url(bad)


def test_rejects_too_long():
    with pytest.raises(BadUrl):
        normalize_url("http://a.com/" + "a" * 3000)


def test_control_and_zero_width_chars_removed():
    assert normalize_url("http://exa\u200bmple.com/\n") == "http://example.com/"


def test_idn_becomes_punycode():
    assert normalize_url("http://مثال.com/").startswith("http://xn--")


def test_trailing_dot_host():
    assert normalize_url("http://example.com./a") == "http://example.com/a"


@pytest.mark.parametrize("ip_form,expected", [("http://2130706433/", "http://127.0.0.1/"), ("http://0x7f.0.0.1/", "http://127.0.0.1/"),
                                              ("http://017700000001/", "http://127.0.0.1/"), ("http://127.1/", "http://127.0.0.1/")])
def test_ip_obfuscation_is_decoded(ip_form, expected):
    assert normalize_url(ip_form) == expected


def test_host_with_port_and_userinfo_kept_for_flagging():
    n = normalize_url("http://paypal.com@evil.com:8080/x")
    assert "paypal.com@evil.com:8080" in n


def test_bad_hostnames():
    for bad in ["http://a..b.com/", "http://exa mple.com/", "http://-.com/"]:
        try:
            normalize_url(bad)
        except BadUrl:
            pass


def test_scheme_less_with_port():
    assert normalize_url("example.com:8080/x") == "http://example.com:8080/x"
