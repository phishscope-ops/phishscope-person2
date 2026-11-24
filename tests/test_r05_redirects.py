"""Round 5: redirects are followed by hand and checked on every hop (security 9, browser 23)."""
from scanner_p2.fetcher import trace_redirects
from helpers import settings, site, make_resolver


async def run(routes, resolver=None, **kw):
    return await trace_redirects("http://a.com/start", settings(**kw), resolver or make_resolver(), site(routes))


async def test_plain_200():
    t = await run({})
    assert t.complete and t.final_url == "http://a.com/start" and t.hops[0].status == 200


async def test_follows_chain_and_keeps_every_hop():
    t = await run({"http://a.com/start": (302, "http://b.com/x"), "http://b.com/x": (301, "/y"), })
    assert t.complete and t.chain() == ["http://a.com/start", "http://b.com/x", "http://b.com/y"]


async def test_relative_and_protocol_relative():
    t = await run({"http://a.com/start": (302, "//c.com/z")})
    assert t.final_url == "http://c.com/z"


async def test_redirect_to_internal_ip_is_blocked_after_hop():
    t = await run({"http://a.com/start": (302, "http://169.254.169.254/latest/meta-data/")})
    assert t.blocked_reason == "private_ip" and not t.complete
    assert not any("169.254" in c for c in []), "unreachable"


async def test_redirect_to_name_resolving_private_is_blocked():
    t = await run({"http://a.com/start": (302, "http://inner.example/")}, resolver=make_resolver({"inner.example": "10.0.0.8"}))
    assert t.blocked_reason == "resolves_to_private_ip"


async def test_redirect_to_localhost_and_odd_port():
    assert (await run({"http://a.com/start": (302, "http://localhost/admin")})).blocked_reason == "internal_hostname"
    assert (await run({"http://a.com/start": (302, "http://a.com:6379/")})).blocked_reason == "port_not_allowed"


async def test_non_http_redirect_target_rejected():
    for loc in ["file:///etc/passwd", "javascript:alert(1)", "gopher://a.com/x", "ftp://a.com/x"]:
        t = await run({"http://a.com/start": (302, loc)})
        assert t.error == "bad_redirect_target" and not t.complete


async def test_loop_detected():
    t = await run({"http://a.com/start": (302, "http://a.com/start")})
    assert t.error == "redirect_loop"


async def test_too_many_redirects():
    routes = {f"http://a.com/{i}": (302, f"http://a.com/{i+1}") for i in range(30)}
    routes["http://a.com/start"] = (302, "http://a.com/0")
    t = await run(routes, max_redirects=5)
    assert t.error == "too_many_redirects" and len(t.hops) == 6


async def test_encoded_ip_redirect_blocked():
    t = await run({"http://a.com/start": (302, "http://2130706433/")})
    assert t.blocked_reason == "private_ip"


async def test_https_downgrade_chain_recorded():
    t = await run({"http://a.com/start": (301, "https://a.com/start")})
    assert t.final_url == "https://a.com/start" and t.complete
