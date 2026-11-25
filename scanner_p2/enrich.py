"""Hand-off fields for the Risk Engine teammate (Person 3) and history owner (Person 1).
This service's verdict is a COMPONENT verdict; the final verdict belongs to the Evidence & Risk Engine."""


def severity(verdict: str, score: int) -> str:
    if verdict == "unknown":
        return "unknown"
    if verdict == "safe":
        return "none"
    base = "low" if score < 30 else "medium" if score < 60 else "high" if score < 80 else "critical"
    if verdict == "malicious" and base in ("low", "medium"):
        return "high"
    return base


def evidence_items(res: dict) -> list:
    items = []
    ev = res.get("evidence") or {}
    for e in ev.get("engine", []) or []:
        items.append({"source": "engine:" + str(e.get("engine", "")), "type": "model_result", "state": e.get("state"),
                      "label": e.get("label"), "score": e.get("score"), "detail": e.get("reasons", [])})
    for t in ev.get("threat_intel", []) or []:
        items.append({"source": "intel:" + str(t.get("provider", "")), "type": "threat_intel", "state": t.get("state"),
                      "label": t.get("verdict"), "detail": t.get("detail")})
    r = ev.get("redirects")
    if r:
        items.append({"source": "redirect_trace", "type": "redirects", "state": "complete" if r.get("complete") else "incomplete",
                      "detail": {"hops": r.get("hop_count"), "chain": r.get("chain_defanged"), "blocked": r.get("blocked_reason")}})
    for why in res.get("reasons", []) or []:
        items.append({"source": "p2_rules", "type": "reason", "detail": why})
    for l in res.get("links", []) or []:
        items.append({"source": "link", "type": "link_result", "label": l.get("verdict"), "detail": l.get("url_defanged")})
    return items


def enrich(res: dict, client_ref=None) -> dict:
    if not isinstance(res, dict):
        return res
    v, s = res.get("verdict", "unknown"), int(res.get("risk_score", 0) or 0)
    res["severity"] = severity(v, s)
    res["scanner_verdict"] = v          # component verdict; final verdict is Person 3's
    res["evidence_items"] = evidence_items(res)
    if client_ref is not None:
        res["client_ref"] = client_ref
    return res
