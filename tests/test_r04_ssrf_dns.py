"""Round 4: DNS answers and ports (security 8, 9)."""
import socket
import pytest
from scanner_p2.ssrf import SsrfBlocked, check_destination
from helpers import make_resolver

P = (80, 443, 8080, 8443)


async def test_public_host_ok():
    assert await check_destination("example.com", 443, P, make_resolver()) == ["93.184.216.34"]


async def test_host_resolving_to_private_is_blocked():
    with pytest.raises(SsrfBlocked) as e:
        await check_destination("evil.com", 80, P, make_resolver({"evil.com": "10.0.0.1"}))
    assert e.value.reason == "resolves_to_private_ip"


async def test_one_private_answer_among_public_blocks_all():
    with pytest.raises(SsrfBlocked):
        await check_destination("evil.com", 80, P, make_resolver({"evil.com": ["93.184.216.34", "127.0.0.1"]}))


async def test_ipv6_mapped_private_blocked():
    with pytest.raises(SsrfBlocked):
        await check_destination("evil.com", 80, P, make_resolver({"evil.com": "::ffff:192.168.0.1"}))


async def test_dns_failure_blocked_not_crash():
    with pytest.raises(SsrfBlocked) as e:
        await check_destination("nx.example", 80, P, make_resolver({"nx.example": None}))
    assert e.value.reason == "dns_failed"


@pytest.mark.parametrize("port", [22, 25, 3306, 6379, 5432, 9200, 11211, 27017, 81, 8000])
async def test_odd_ports_blocked(port):
    with pytest.raises(SsrfBlocked) as e:
        await check_destination("example.com", port, P, make_resolver())
    assert e.value.reason == "port_not_allowed"


@pytest.mark.parametrize("host", ["127.0.0.1", "[::1]", "169.254.169.254", "10.1.2.3", "localhost"])
async def test_literal_internal_hosts(host):
    with pytest.raises(SsrfBlocked):
        await check_destination(host, 80, P, make_resolver())


async def test_rebinding_second_answer_not_used():
    """The check returns the vetted IPs. The caller connects to these, it never resolves again."""
    calls = []

    async def flip(host, port):
        calls.append(1)
        return ["93.184.216.34"] if len(calls) == 1 else ["127.0.0.1"]
    ips = await check_destination("rebind.com", 80, P, flip)
    assert ips == ["93.184.216.34"] and len(calls) == 1
