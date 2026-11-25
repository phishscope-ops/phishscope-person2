"""URL parsing, normalisation, defanging and link extraction (requirements 1, 2)."""
import ipaddress
import re
import socket
from urllib.parse import urlsplit, urlunsplit, unquote

ALLOWED_SCHEMES = {"http", "https"}
_CTRL = re.compile(r"[\x00-\x20\x7f\u200b-\u200f\u202a-\u202e\u2060\ufeff]")


class BadUrl(ValueError):
    pass


def defang(value: str) -> str:
    """Never show or store a live link: https://a.com -> hxxps://a[.]com"""
    value = re.sub(r"(?i)^http", "hxxp", value)
    return value.replace(".", "[.]")


def refang(value: str) -> str:
    value = value.strip().replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")
    return re.sub(r"(?i)^hxxp", "http", value)


def parse_ip_literal(host: str):
    """Return an ip_address for plain, decimal, hex, octal and short IPv4 forms, or None."""
    h = host.strip("[]")
    try:
        return ipaddress.ip_address(h)
    except ValueError:
        pass
    if re.fullmatch(r"[0-9a-fA-Fx.]+", h) and any(c.isdigit() for c in h):
        try:
            return ipaddress.ip_address(socket.inet_aton(h))  # accepts 2130706433, 0x7f.1, 017700000001
        except (OSError, ValueError):
            return None
    return None


def normalize_url(raw: str, max_len: int = 2048) -> str:
    if not isinstance(raw, str):
        raise BadUrl("not text")
    raw = refang(raw)
    if len(raw) > max_len:
        raise BadUrl("url too long")
    raw = _CTRL.sub("", raw)
    if not raw:
        raise BadUrl("empty url")
    if "://" not in raw:
        if re.match(r"(?i)^[a-z][a-z0-9+.-]*:", raw) and not re.match(r"(?i)^[^/]+:\d+(/|$)", raw):
            raise BadUrl("scheme not allowed")
        raw = "http://" + raw.lstrip("/")
    try:
        parts = urlsplit(raw)
        host = (parts.hostname or "").rstrip(".").lower()
        port = parts.port
    except ValueError:
        raise BadUrl("malformed url")
    if parts.scheme.lower() not in ALLOWED_SCHEMES:
        raise BadUrl("scheme not allowed")
    if not host:
        raise BadUrl("no host")
    if re.search(r"[\s<>\"'\\^`{|}]", host):
        raise BadUrl("invalid characters in host")
    ip = parse_ip_literal(host)
    if ip is not None:
        host = f"[{ip}]" if ip.version == 6 else str(ip)
    else:
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            raise BadUrl("bad host name")
        if not re.fullmatch(r"[a-z0-9_.-]+", host) or ".." in host or len(host) > 253:
            raise BadUrl("bad host name")
    netloc = host
    if parts.username:  # keep userinfo, it is a phishing signal; callers flag it
        netloc = f"{parts.username}{':' + parts.password if parts.password else ''}@{host}"
    if port:
        netloc += f":{port}"
    return urlunsplit((parts.scheme.lower(), netloc, parts.path or "/", parts.query, ""))


_URL_RE = re.compile(r"(?i)\b(?:https?://|hxxps?://|www\.)[^\s<>\"'\u200b]+")
_BARE_RE = re.compile(r"(?i)\b(?:[a-z0-9-]{1,63}\.){1,10}(?:xn--[a-z0-9-]{2,59}|[a-z]{2,24})(?![a-z0-9-])(?::\d+)?(?:[/?#][^\s<>\"']*)?")
_TRAIL = ".,);]}،؛؟!\"'>"


def extract_urls(text: str, limit: int = 10) -> list:
    """Find links in free text (SMS, email bodies). Returns normalised, de-duplicated links."""
    text = (text or "")[:100000]
    text = re.sub(r"\S{600,}", lambda m: m.group(0)[:600], text)  # bound the work on hostile input
    explicit = list(_URL_RE.finditer(text))
    def _is_email_part(m):
        before = text[m.start() - 1:m.start()] if m.start() else ""
        after = text[m.end():m.end() + 1]
        return before == "@" or after == "@"

    bare = [m for m in _BARE_RE.finditer(text)
            if not any(m.start() < e.end() and m.end() > e.start() for e in explicit)
            and not _is_email_part(m)]
    out, seen = [], set()
    for m in sorted(explicit + bare, key=lambda m: m.start()):
        cand = m.group(0).rstrip(_TRAIL)
        try:
            n = normalize_url(cand)
        except BadUrl:
            continue
        host = urlsplit(n).hostname or ""
        # skip things like "file.txt" or "3.14": a link needs a real-looking TLD or an explicit scheme
        if not re.match(r"(?i)^(https?|hxxps?)://", cand) and not cand.lower().startswith("www."):
            tld = host.rsplit(".", 1)[-1]
            if parse_ip_literal(host) is None and (tld.isdigit() or tld in _FILE_EXT):
                continue
        if n not in seen:
            seen.add(n)
            out.append(n)
        if len(out) >= limit:
            break
    return out


_FILE_EXT = {"txt", "pdf", "doc", "docx", "xls", "xlsx", "png", "jpg", "jpeg", "gif", "zip", "exe", "py", "js", "html", "htm", "css", "json", "md", "csv", "mp3", "mp4", "apk"}


def host_of(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def percent_decoded_path(url: str) -> str:
    return unquote(urlsplit(url).path)
