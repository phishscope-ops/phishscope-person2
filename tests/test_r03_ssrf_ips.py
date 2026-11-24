"""Round 3: SSRF, internal and private addresses (security 8)."""
import ipaddress
import pytest
from scanner_p2.ssrf import ip_is_blocked, host_name_is_blocked

BLOCKED = ["127.0.0.1", "10.0.0.5", "172.16.0.1", "172.31.255.255", "192.168.1.1", "169.254.169.254", "0.0.0.0", "100.64.0.1",
           "224.0.0.1", "255.255.255.255", "::1", "::", "fe80::1", "fc00::1", "fd12:3456::1", "::ffff:127.0.0.1", "::ffff:10.1.1.1",
           "::ffff:169.254.169.254", "2002:7f00:0001::1", "64:ff9b::7f00:1", "192.0.2.1", "198.51.100.7", "203.0.113.9", "240.0.0.1"]
ALLOWED = ["93.184.216.34", "8.8.8.8", "1.1.1.1", "2606:2800:220:1:248:1893:25c8:1946", "104.16.0.1"]


@pytest.mark.parametrize("ip", BLOCKED)
def test_blocked(ip):
    assert ip_is_blocked(ip)


@pytest.mark.parametrize("ip", ALLOWED)
def test_allowed(ip):
    assert not ip_is_blocked(ip)


@pytest.mark.parametrize("h", ["localhost", "LOCALHOST", "foo.localhost", "db.internal", "printer.local", "metadata.google.internal",
                               "router.lan", "x.corp", "localhost."])
def test_internal_names(h):
    assert host_name_is_blocked(h)


def test_public_names_ok():
    assert not host_name_is_blocked("example.com") and not host_name_is_blocked("local-news.com")


def test_every_private_range_edge():
    for net in ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16"]:
        n = ipaddress.ip_network(net)
        assert ip_is_blocked(n[0]) and ip_is_blocked(n[-1])
    assert not ip_is_blocked("172.32.0.1") and not ip_is_blocked("11.0.0.1")
