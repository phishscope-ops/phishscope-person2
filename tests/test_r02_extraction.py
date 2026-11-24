"""Round 2: finding links inside SMS and email text."""
from scanner_p2.urlnorm import extract_urls


def test_arabic_sms_with_link_and_punctuation():
    t = "تم إيقاف حسابك، اضغط هنا: https://bank-verify.top/login؟ عاجل!"
    assert extract_urls(t) == ["https://bank-verify.top/login"]


def test_trailing_punctuation_removed():
    assert extract_urls("see (http://a.com/x).") == ["http://a.com/x"]


def test_www_and_bare_domains():
    assert extract_urls("go to www.evil.com/a or evil2.top") == ["http://www.evil.com/a", "http://evil2.top/"]


def test_emails_are_not_links():
    assert extract_urls("mail me at john.doe@mail.com please") == []


def test_file_names_and_numbers_are_not_links():
    assert extract_urls("see report.pdf and v1.2 and 3.14 and notes.txt") == []


def test_dedupe_and_limit():
    t = " ".join(f"http://a{i}.com/" for i in range(30)) + " http://a1.com/"
    assert len(extract_urls(t, 10)) == 10
    assert extract_urls("http://a.com http://a.com") == ["http://a.com/"]


def test_defanged_links_found():
    assert extract_urls("hxxps://evil[.]com/x") == ["https://evil.com/x"]


def test_javascript_and_data_ignored():
    assert extract_urls("javascript:alert(1) data:text/html,x") == []


def test_ip_links_found():
    assert extract_urls("open http://192.168.1.1/a") == ["http://192.168.1.1/a"]


def test_empty_none():
    assert extract_urls("") == [] and extract_urls(None) == []


def test_huge_text_is_fast():
    import time
    t0 = time.time()
    extract_urls("a" * 200000 + " http://a.com")
    extract_urls("a.b." * 50000)
    assert time.time() - t0 < 5
