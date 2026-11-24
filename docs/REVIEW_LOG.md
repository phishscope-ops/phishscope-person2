# Review log (17 rounds, 223 tests; final run: 223 passed)
r01 URL parsing | r02 URL extraction from text | r03 SSRF IP ranges | r04 SSRF DNS (rebinding, mixed answers) | r05 redirects |
r06 limits | r07 threat intel | r08 verdict logic | r09 URL end to end | r10 email headers | r11 email links/attachments |
r12 SMS | r13 automatic protection | r14 secure browser | r15 ML engine adapter | r16 API contract + log redaction | r17 fuzz and hostile input.

## Real bugs found by the rounds and fixed
1. Regex backtracking on hostile text (slow). Fix: token and text caps (100k).
2. Malformed Location header crashed httpx. Fix: caught as bad_redirect_target (unknown, never safe).
3. Email display-name spoof read wrongly. Fix: parseaddr.
4. Reply-To mismatch and display-name spoof were too weak. Weights raised so each alone gives suspicious.
5. Browser deadline ignored the app setting. Fix: deadline applied from the scanner settings.
6. Bearer token not masked in logs when a header name preceded it. Fix: pattern order in logsafe.

## Live smoke (real network)
example.com over HTTPS with IP pinning: safe/allow, redirect trace complete. 127.0.0.1 and 169.254.169.254: blocked, never fetched.

## Honest limits
- Without a teammate engine, local heuristics run (marked degraded); accuracy then depends on the ML teammate's engine.
- VirusTotal and blocklist are optional; without them the result says so and confidence is "limited".
- Not tested against the real mobile app, ML engine or database of the team (they are not part of this scope); contract tests only.
