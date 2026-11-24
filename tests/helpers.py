import httpx
from scanner_p2.config import Settings
from scanner_p2.engines import Engines
from scanner_p2.intel import IntelHub, LocalBlocklist
from scanner_p2.scanners import Scanner

PUBLIC = "93.184.216.34"


def settings(**kw) -> Settings:
    s = Settings()
    s.engine_url_base, s.vt_api_key, s.blocklist_file, s.api_key = "", "", "", ""
    s.db_path = ":memory:"
    for k, v in kw.items():
        setattr(s, k, v)
    return s


def make_resolver(mapping=None, default=PUBLIC):
    mapping = mapping or {}

    async def r(host, port):
        v = mapping.get(host, default)
        if v is None:
            import socket
            raise socket.gaierror("nx")
        return v if isinstance(v, list) else [v]
    return r


def site(routes=None, default=200):
    """routes: {url: (status, location)}; anything else answers `default`."""
    routes = routes or {}
    calls = []

    def handler(req: httpx.Request):
        calls.append(str(req.url))
        st = routes.get(str(req.url))
        if st is None:
            return httpx.Response(default, content=b"<html>hi</html>")
        code, loc = st
        return httpx.Response(code, headers={"location": loc} if loc else {}, content=b"")
    t = httpx.MockTransport(handler)
    t.calls = calls
    return t


def scanner(routes=None, resolver=None, intel=None, engines=None, **kw):
    s = settings(**kw)
    tr = site(routes)
    sc = Scanner(s, engines=engines or Engines(s), intel=intel or IntelHub(s, providers=[]),
                 resolver=resolver or make_resolver(), transport=tr)
    sc.tr = tr
    return sc


class FakeIntel:
    def __init__(self, results):
        self.results = results
        self.name = "fake"

    async def check(self, url):
        r = self.results
        if isinstance(r, Exception):
            raise r
        return r
