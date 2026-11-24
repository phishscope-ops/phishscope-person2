"""Sensitive data must not reach logs (security 11). We never log message bodies or query strings,
and a filter masks anything that looks like a key, token, email, phone number or long digit code."""
import logging
import re

_PATTERNS = [
    (re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]{8,}"), r"\1 ***"),
    (re.compile(r"(?i)(x-apikey|authorization|api[_-]?key|token|secret|password|passwd|bearer)(\s*[:=]\s*|\s+)([^\s,;&\"']+)"), r"\1\2***"),
    (re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"), "***@***"),
    (re.compile(r"(?<!\d)\+?\d[\d\s-]{8,16}\d(?!\d)"), "***phone***"),
    (re.compile(r"\b[A-Fa-f0-9]{32,}\b"), "***hash***"),
    (re.compile(r"\b[A-Za-z0-9_-]{32,}\b"), "***key***"),
    (re.compile(r"(\?[^\s\"']*)"), "?***"),
]


def scrub(text: str) -> str:
    for pat, rep in _PATTERNS:
        text = pat.sub(rep, text)
    return text


class RedactFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            record.msg = scrub(record.getMessage())
            record.args = ()
        except Exception:
            record.msg = "[log message hidden]"
            record.args = ()
        return True


def get_logger(name="scanner_p2") -> logging.Logger:
    log = logging.getLogger(name)
    if not any(isinstance(f, RedactFilter) for f in log.filters):
        log.addFilter(RedactFilter())
    if not log.handlers:
        h = logging.StreamHandler()
        h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        h.addFilter(RedactFilter())
        log.addHandler(h)
        log.setLevel(logging.INFO)
        log.propagate = False
    return log
