"""Safe redirect tracer (Secure Browser 23, security 9, 10).
No JavaScript is run and no page content is kept. We follow redirects by hand, re-checking every hop,
pin the connection to the vetted IP, and cap time, hops and response size."""
import asyncio
import time
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urljoin, urlsplit

import httpx

from .config import Settings
from .ssrf import SsrfBlocked, check_destination, system_resolver, Resolver
from .urlnorm import BadUrl, normalize_url

UA = "Mozilla/5.0 (compatible; PhishScopeScanner/1.0; +link-check)"


@dataclass
class Hop:
    url: str
    status: Optional[int] = None
    ip: Optional[str] = None
    ms: int = 0
    note: str = ""


@dataclass
class Trace:
    start_url: str
    hops: List[Hop] = field(default_factory=list)
    final_url: str = ""
    complete: bool = False          # True only when we reached a final non-redirect answer
    blocked_reason: str = ""        # set when SSRF protection refused a hop
    error: str = ""                 # timeout, dns_failed, too_many_redirects, redirect_loop, tls_error, ...
    truncated: bool = False
    content_type: str = ""

    def chain(self) -> List[str]:
        return [h.url for h in self.hops]


async def trace_redirects(url: str, settings: Settings, resolver: Resolver = system_resolver,
                          transport: Optional[httpx.AsyncBaseTransport] = None) -> Trace:
    """`transport` is only for tests. In production the real network transport is used."""
    tr = Trace(start_url=url, final_url=url)
    deadline = time.monotonic() + settings.fetch_total_deadline
    current, seen = url, set()
    async with httpx.AsyncClient(transport=transport, follow_redirects=False, verify=True,
                                 timeout=httpx.Timeout(settings.fetch_timeout),
                                 headers={"User-Agent": UA, "Accept": "text/html,*/*;q=0.5"},
                                 limits=httpx.Limits(max_connections=2)) as client:
        for _ in range(settings.max_redirects + 1):
            if time.monotonic() > deadline:
                tr.error = "timeout"
                return tr
            try:
                current = normalize_url(current, settings.max_url_len)
            except BadUrl:
                tr.error = "bad_redirect_target"
                return tr
            if current in seen:
                tr.error = "redirect_loop"
                return tr
            seen.add(current)
            parts = urlsplit(current)
            host = parts.hostname or ""
            port = parts.port or (443 if parts.scheme == "https" else 80)
            hop = Hop(url=current)
            tr.hops.append(hop)
            tr.final_url = current
            try:  # the destination check runs on EVERY hop, including the first
                ips = await check_destination(host, port, settings.allowed_ports, resolver)
            except SsrfBlocked as e:
                hop.note = "blocked:" + e.reason
                tr.blocked_reason = e.reason
                return tr
            hop.ip = ips[0]
            t0 = time.monotonic()
            try:
                resp = await _one_request(client, parts, host, port, ips[0], settings, deadline, transport)
            except httpx.TimeoutException:
                tr.error = "timeout"
                return tr
            except (httpx.InvalidURL, httpx.UnsupportedProtocol):
                tr.error = "bad_redirect_target"  # httpx rejects the Location header itself
                return tr
            except httpx.ConnectError as e:
                tr.error = "tls_error" if "CERTIFICATE" in str(e).upper() or "SSL" in str(e).upper() else "connect_error"
                return tr
            except httpx.HTTPError:
                tr.error = "http_error"
                return tr
            except asyncio.TimeoutError:
                tr.error = "timeout"
                return tr
            hop.ms = int((time.monotonic() - t0) * 1000)
            hop.status = resp[0]
            tr.content_type = resp[2]
            tr.truncated = resp[3]
            loc = resp[1]
            if hop.status in (301, 302, 303, 307, 308) and loc:
                current = urljoin(current, loc)
                continue
            tr.complete = True
            return tr
        tr.error = "too_many_redirects"
        return tr


async def _one_request(client, parts, host, port, ip, settings, deadline, transport):
    """GET with a hard body cap. Connects to the vetted IP, keeps the real host for Host header and TLS name."""
    target = parts.geturl()
    ext = {}
    req_url = target
    if transport is None:  # pin to the vetted IP; tests with a mock transport use the name directly
        ip_host = f"[{ip}]" if ":" in ip else ip
        netloc = f"{ip_host}:{port}" if parts.port else ip_host
        req_url = parts._replace(netloc=netloc).geturl()
        ext = {"sni_hostname": host}
    req = client.build_request("GET", req_url, headers={"Host": parts.netloc.split("@")[-1]}, extensions=ext)
    remaining = max(0.5, deadline - time.monotonic())
    async def run():
        r = await client.send(req, stream=True)
        try:
            total, truncated = 0, False
            async for chunk in r.aiter_bytes():
                total += len(chunk)
                if total >= settings.max_response_bytes:
                    truncated = True
                    break
            return r.status_code, r.headers.get("location", ""), r.headers.get("content-type", ""), truncated
        finally:
            await r.aclose()
    return await asyncio.wait_for(run(), timeout=remaining)
