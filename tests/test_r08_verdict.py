"""Round 8: the verdict rules, one by one (requirement 4, 24, 28)."""
from scanner_p2.engines import EngineResult
from scanner_p2.fetcher import Trace
from scanner_p2.intel import IntelResult
from scanner_p2.verdict import judge

OK = EngineResult("ok", "e", "1", "legit", 0.05, [])
DONE = Trace("http://a.com/", final_url="http://a.com/", complete=True)


def j(engs=None, intel=None, traces=None, extra=None):
    return judge(engs if engs is not None else [OK], intel if intel is not None else [], traces if traces is not None else [DONE], extra)


def test_clean_everything_is_safe_with_limited_confidence_without_ti():
    r = j()
    assert r.verdict == "safe" and r.confidence == "limited" and any("مصدر تهديدات" in c for c in r.caveats)


def test_safe_with_working_ti_has_normal_confidence():
    r = j(intel=[IntelResult("vt", "inconclusive", None, "no_detections_not_a_safety_proof")])
    assert r.verdict == "safe" and r.confidence == "normal"


def test_engine_down_is_unknown_never_safe():
    assert j(engs=[EngineResult("unavailable", detail="x")]).verdict == "unknown"
    assert j(engs=[EngineResult("degraded", "local", "1", "legit", 0.0)]).verdict == "unknown"
    assert j(engs=[]).verdict == "unknown"


def test_unfinished_redirect_trace_is_unknown():
    for err in ["timeout", "dns_failed", "connect_error", "tls_error", "http_error"]:
        assert j(traces=[Trace("u", final_url="u", error=err)]).verdict == "unknown", err


def test_blocked_internal_destination_is_at_least_suspicious():
    r = j(traces=[Trace("u", final_url="u", blocked_reason="private_ip")])
    assert r.verdict == "suspicious"


def test_redirect_loop_is_suspicious():
    assert j(traces=[Trace("u", final_url="u", error="redirect_loop")]).verdict == "suspicious"


def test_ti_malicious_wins_over_clean_engine():
    r = j(intel=[IntelResult("vt", "confirmed", "malicious", "x")])
    assert r.verdict == "malicious" and r.risk_score >= 90


def test_ti_suspicious_is_suspicious():
    assert j(intel=[IntelResult("vt", "confirmed", "suspicious")]).verdict == "suspicious"


def test_all_ti_unavailable_never_safe_by_ti_and_says_so():
    r = j(intel=[IntelResult("vt", "unavailable", detail="no_api_key")])
    assert r.verdict == "safe" and r.confidence == "limited"
    assert any("مش دليل" in c for c in r.caveats)


def test_high_engine_score_malicious():
    e = EngineResult("ok", "e", "1", "phishing", 0.93, ["x"])
    assert j(engs=[e]).verdict == "malicious"


def test_medium_engine_score_suspicious():
    e = EngineResult("ok", "e", "1", "suspicious", 0.5, ["x"])
    assert j(engs=[e]).verdict == "suspicious"


def test_reasons_deduplicated():
    e = EngineResult("ok", "e", "1", "suspicious", 0.5, ["same", "same"])
    assert j(engs=[e]).reasons.count("same") == 1


def test_https_gives_no_credit():
    from scanner_p2.engines import url_heuristics
    a, _ = url_heuristics("http://secure-login-bank.top/verify", {})
    b, _ = url_heuristics("https://secure-login-bank.top/verify", {})
    assert b >= a - 0.05 and b >= 0.35
