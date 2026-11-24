"""All settings come from environment variables. Every one has a safe default, so the service runs with nothing set."""
import os
from dataclasses import dataclass, field


def _i(name, default):
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def _f(name, default):
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        return default


@dataclass
class Settings:
    # Teammate engines (ML). Empty means "use the built-in local heuristics".
    engine_url_base: str = field(default_factory=lambda: os.environ.get("P2_ENGINE_URL_BASE", "").rstrip("/"))
    engine_api_key: str = field(default_factory=lambda: os.environ.get("P2_ENGINE_API_KEY", ""))
    engine_timeout: float = field(default_factory=lambda: _f("P2_ENGINE_TIMEOUT", 3.0))
    # Threat intelligence (all optional).
    vt_api_key: str = field(default_factory=lambda: os.environ.get("VT_API_KEY", ""))
    blocklist_file: str = field(default_factory=lambda: os.environ.get("P2_BLOCKLIST_FILE", ""))
    intel_timeout: float = field(default_factory=lambda: _f("P2_INTEL_TIMEOUT", 4.0))
    intel_cache_seconds: int = field(default_factory=lambda: _i("P2_INTEL_CACHE_SECONDS", 3600))
    # Outbound fetch limits (SSRF section).
    fetch_timeout: float = field(default_factory=lambda: _f("P2_FETCH_TIMEOUT", 4.0))
    fetch_total_deadline: float = field(default_factory=lambda: _f("P2_FETCH_DEADLINE", 10.0))
    max_redirects: int = field(default_factory=lambda: _i("P2_MAX_REDIRECTS", 5))
    max_response_bytes: int = field(default_factory=lambda: _i("P2_MAX_RESPONSE_BYTES", 65536))
    allowed_ports: tuple = (80, 443, 8080, 8443)
    # Input limits.
    max_url_len: int = field(default_factory=lambda: _i("P2_MAX_URL_LEN", 2048))
    max_sms_len: int = field(default_factory=lambda: _i("P2_MAX_SMS_LEN", 2000))
    max_email_bytes: int = field(default_factory=lambda: _i("P2_MAX_EMAIL_BYTES", 5_000_000))
    max_links_per_item: int = field(default_factory=lambda: _i("P2_MAX_LINKS", 10))
    # Latency budgets.
    protection_deadline: float = field(default_factory=lambda: _f("P2_PROTECTION_DEADLINE", 6.0))
    browser_deadline: float = field(default_factory=lambda: _f("P2_BROWSER_DEADLINE", 12.0))
    # Access and abuse limits.
    api_key: str = field(default_factory=lambda: os.environ.get("P2_API_KEY", ""))
    rate_limit_per_minute: int = field(default_factory=lambda: _i("P2_RATE_LIMIT", 120))
    db_path: str = field(default_factory=lambda: os.environ.get("P2_DB_PATH", "p2_scans.sqlite3"))
    scan_ttl_seconds: int = field(default_factory=lambda: _i("P2_SCAN_TTL", 7 * 86400))
    max_concurrent_scans: int = field(default_factory=lambda: _i("P2_MAX_CONCURRENT", 8))


def get_settings() -> Settings:
    return Settings()
