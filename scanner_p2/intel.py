"""Threat Intelligence (25 to 28). Providers are optional and free. A missing, failed or empty answer is
never treated as 'safe': it becomes state 'unavailable' or 'inconclusive', and the verdict logic knows that."""
import base64
import time
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional
from urllib.parse import urlsplit

import httpx

from .config import Settings


@dataclass
class IntelResult:
    provider: str
    state: str                      # confirmed | inconclusive | unavailable
    verdict: Optional[str] = None   # malicious | suspicious | None. Never 'safe'.
    detail: str = ""
    stats: Dict = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)


def registered_domain(host: str) -> str:
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    # small built-in list of common two-label public suffixes, enough for the markets we serve
    if ".".join(parts[-2:]) in {"com.eg", "gov.eg", "edu.eg", "org.eg", "net.eg", "co.uk", "org.uk", "com.sa", "com.au", "co.in"}:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


class LocalBlocklist:
    """A plain text file, one domain or full URL per line. Works offline and costs nothing."""
    name = "local_blocklist"

    def __init__(self, path: str):
        self.domains, self.urls = set(), set()
        if path:
            try:
                for line in open(path, encoding="utf-8"):
                    line = line.strip().lower()
                    if not line or line.startswith("#"):
                        continue
                    (self.urls if "/" in line else self.domains).add(line.rstrip("/"))
            except OSError:
                pass
        self.enabled = bool(self.domains or self.urls)

    async def check(self, url: str) -> IntelResult:
        if not self.enabled:
            return IntelResult(self.name, "unavailable", detail="no_blocklist_configured")
        host = (urlsplit(url).hostname or "").lower()
        if url.lower().rstrip("/") in self.urls or host in self.domains or registered_domain(host) in self.domains:
            return IntelResult(self.name, "confirmed", "malicious", "listed_in_local_blocklist")
        return IntelResult(self.name, "inconclusive", None, "not_listed")


class VirusTotal:
    name = "virustotal"

    def __init__(self, settings: Settings, transport=None):
        self.key, self.timeout, self.ttl = settings.vt_api_key, settings.intel_timeout, settings.intel_cache_seconds
        self.transport = transport
        self._cache: Dict[str, tuple] = {}

    async def check(self, url: str) -> IntelResult:
        if not self.key:
            return IntelResult(self.name, "unavailable", detail="no_api_key")
        hit = self._cache.get(url)
        if hit and hit[0] > time.time():
            return hit[1]
        uid = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        try:
            async with httpx.AsyncClient(timeout=self.timeout, transport=self.transport) as c:
                r = await c.get(f"https://www.virustotal.com/api/v3/urls/{uid}", headers={"x-apikey": self.key})
        except httpx.HTTPError:
            return IntelResult(self.name, "unavailable", detail="request_failed")
        if r.status_code == 404:
            res = IntelResult(self.name, "inconclusive", None, "url_not_known_to_provider")
        elif r.status_code == 429:
            return IntelResult(self.name, "unavailable", detail="quota_exceeded")
        elif r.status_code != 200:
            return IntelResult(self.name, "unavailable", detail=f"http_{r.status_code}")
        else:
            try:
                stats = r.json()["data"]["attributes"]["last_analysis_stats"]
                mal, sus = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0))
            except (KeyError, ValueError, TypeError):
                return IntelResult(self.name, "unavailable", detail="bad_response")
            if mal >= 2:
                res = IntelResult(self.name, "confirmed", "malicious", f"{mal}_engines_flag_malicious", stats)
            elif mal == 1 or sus >= 1:
                res = IntelResult(self.name, "confirmed", "suspicious", "some_engines_flag_it", stats)
            else:
                # 0 detections is NOT a safety proof; it only means this source knows nothing bad.
                res = IntelResult(self.name, "inconclusive", None, "no_detections_not_a_safety_proof", stats)
        self._cache[url] = (time.time() + self.ttl, res)
        return res


class IntelHub:
    def __init__(self, settings: Settings, providers=None):
        self.providers = providers if providers is not None else [LocalBlocklist(settings.blocklist_file), VirusTotal(settings)]
        self.settings = settings

    async def lookup(self, urls: List[str]) -> List[IntelResult]:
        """Check every URL in the redirect chain: a bad middle hop matters even if the landing page looks clean."""
        import asyncio
        out: List[IntelResult] = []
        for u in urls:
            for p in self.providers:
                try:
                    r = await asyncio.wait_for(p.check(u), timeout=self.settings.intel_timeout + 1)
                except Exception:
                    r = IntelResult(getattr(p, "name", "provider"), "unavailable", detail="provider_error")
                r.detail = r.detail
                r.stats = dict(r.stats, url_host=urlsplit(u).hostname or "")
                out.append(r)
        return out
