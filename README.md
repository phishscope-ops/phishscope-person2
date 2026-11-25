# PhishScope - Person 2 Scanner Service

Standalone FastAPI service. Scope: URL Scanner (1-6), Email Scanner (7-12), SMS Scanner, Automatic SMS Protection,
Secure Browser functions (21-24), Threat Intelligence Integration (25-28), Security Responsibilities. Nothing else.

## PHP 8 version
A full PHP 8 port (no framework) lives in `php/`, see `php/README.md`. Tests: `php php/tests/run.php`.

## Run
    python -m venv .venv && . .venv/bin/activate
    pip install -r requirements.txt
    uvicorn main:app --port 8000        # docs: http://localhost:8000/docs
Or: `docker build -t p2 . && docker run -p 8000:8000 p2`

## Test
    pip install -r requirements-dev.txt && pytest -q        # 227 tests, 18 rounds, no network needed

## Settings (all optional, environment variables)
| Variable | Meaning |
|---|---|
| P2_ENGINE_URL_BASE | ML teammate's engine base URL. Empty = built-in local heuristics (marked degraded) |
| P2_ENGINE_API_KEY | Bearer key sent to the engine |
| VT_API_KEY | Free VirusTotal key (optional) |
| P2_BLOCKLIST_FILE | Text file, one bad domain per line (free, optional) |
| P2_API_KEY | If set, every call needs header X-API-Key |
| P2_RATE_LIMIT | Requests per minute per client (default 120) |
| P2_DB_PATH | SQLite file for scan results (default p2_scans.sqlite3) |

## Verdict rules (the important part)
- Verdicts: safe / suspicious / malicious / unknown. Actions: allow / warn / block / warn_unverified.
- "safe" needs a working engine AND a complete redirect trace. HTTPS gives no credit. Missing threat-intel is never counted as safe.
- Any failure (engine down, timeout, blocked redirect, bad input) gives "unknown", never "safe".

## Security
SSRF: only http/https and ports 80/443/8080/8443; every DNS answer is checked; private, loopback, link-local, metadata and
IPv4-mapped IPv6 ranges are blocked; the connection is pinned to the checked IP; each redirect is re-checked (max 5);
response size, time and input sizes are capped; logs are scrubbed (no message text, phones, emails, keys, tokens).

See docs/INTEGRATION_AR.md (how it connects to the team), docs/COVERAGE.md (requirement to code), docs/REVIEW_LOG.md (rounds).
