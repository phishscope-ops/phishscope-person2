"""SSRF protection (security 8, 9, 10). Every outbound address is checked, including after each redirect."""
import asyncio
import ipaddress
import socket
from typing import Awaitable, Callable, List

from .urlnorm import parse_ip_literal


class SsrfBlocked(Exception):
    """The destination is internal, private, reserved, or not allowed. Never fetched."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


_EXTRA_BLOCKED = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15",
    "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "255.255.255.255/32",
    "64:ff9b::/96", "64:ff9b:1::/48", "2001::/32", "2001:db8::/32", "fc00::/7", "fe80::/10", "100::/64",
)]


def ip_is_blocked(ip) -> bool:
    if isinstance(ip, str):
        ip = ipaddress.ip_address(ip.strip("[]"))
    if ip.version == 6:
        if ip.ipv4_mapped is not None:
            return ip_is_blocked(ip.ipv4_mapped)
        if ip.sixtofour is not None and ip_is_blocked(ip.sixtofour):
            return True
        if ip.teredo is not None:
            return True
    if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
            or ip.is_multicast or ip.is_unspecified):
        return True
    return any(ip in net for net in _EXTRA_BLOCKED if net.version == ip.version)


def host_name_is_blocked(host: str) -> bool:
    h = host.strip("[]").lower().rstrip(".")
    return (h in {"localhost", "localhost.localdomain", "ip6-localhost", "metadata", "metadata.google.internal"}
            or h.endswith((".localhost", ".local", ".internal", ".intranet", ".lan", ".home", ".corp", ".localdomain")))


Resolver = Callable[[str, int], Awaitable[List[str]]]


async def system_resolver(host: str, port: int) -> List[str]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return list(dict.fromkeys(i[4][0] for i in infos))


async def check_destination(host: str, port: int, allowed_ports, resolver: Resolver = system_resolver) -> List[str]:
    """Return the safe IP list to connect to, or raise SsrfBlocked. The caller must connect to one of these IPs
    (not re-resolve), so a DNS rebinding answer between check and connect cannot reach an internal address."""
    if port not in allowed_ports:
        raise SsrfBlocked("port_not_allowed")
    if host_name_is_blocked(host):
        raise SsrfBlocked("internal_hostname")
    lit = parse_ip_literal(host)
    if lit is not None:
        if ip_is_blocked(lit):
            raise SsrfBlocked("private_ip")
        return [str(lit)]
    try:
        ips = await resolver(host, port)
    except (socket.gaierror, OSError, UnicodeError):
        raise SsrfBlocked("dns_failed")
    if not ips:
        raise SsrfBlocked("dns_failed")
    for ip in ips:  # one bad address in the answer blocks the whole host
        try:
            if ip_is_blocked(ip.split("%")[0]):
                raise SsrfBlocked("resolves_to_private_ip")
        except ValueError:
            raise SsrfBlocked("dns_bad_answer")
    return ips
