"""Round 6: time, size and request limits (security 10)."""
import asyncio
import httpx
import pytest
from scanner_p2.fetcher import trace_redirects
from scanner_p2.ratelimit import RateLimiter
from helpers import settings, make_resolver, scanner


async def test_big_response_is_cut_at_cap():
    big = httpx.MockTransport(lambda r: httpx.Response(200, content=b"x" * 5_000_000))
    t = await trace_redirects("http://a.com/", settings(max_response_bytes=10000), make_resolver(), big)
    assert t.complete and t.truncated


async def test_slow_server_times_out():
    async def slow(request):
        await asyncio.sleep(3)
        return httpx.Response(200)
    t = await trace_redirects("http://a.com/", settings(fetch_total_deadline=0.5, fetch_timeout=0.4), make_resolver(), httpx.MockTransport(slow))
    assert t.error == "timeout" and not t.complete


async def test_total_deadline_across_hops():
    async def slow(request):
        await asyncio.sleep(0.3)
        return httpx.Response(302, headers={"location": f"http://a.com/{request.url.path.strip('/') or 0}x"})
    t = await trace_redirects("http://a.com/", settings(fetch_total_deadline=0.8, max_redirects=50), make_resolver(), httpx.MockTransport(slow))
    assert t.error in ("timeout", "too_many_redirects") and len(t.hops) < 10


async def test_connect_error_is_reported_not_raised():
    def boom(request):
        raise httpx.ConnectError("refused")
    t = await trace_redirects("http://a.com/", settings(), make_resolver(), httpx.MockTransport(boom))
    assert t.error == "connect_error"


async def test_tls_error_named():
    def boom(request):
        raise httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED]")
    t = await trace_redirects("https://a.com/", settings(), make_resolver(), httpx.MockTransport(boom))
    assert t.error == "tls_error"


def test_rate_limiter_window():
    r = RateLimiter(3)
    assert [r.allow("k", now=i) for i in range(4)] == [True, True, True, False]
    assert r.allow("k", now=61) and r.allow("other", now=1)


async def test_oversize_url_rejected_before_any_request():
    sc = scanner()
    res = await sc.scan_url("http://a.com/" + "a" * 5000)
    assert res["verdict"] == "unknown" and not sc.tr.calls


async def test_sms_is_truncated_to_limit():
    sc = scanner(max_sms_len=50)
    res = await sc.scan_sms("hello " * 1000 + " http://far.example/")
    assert res["links"] == []
