# Requirement to code to test map (Person 2 only)

| Item | Where | Tests |
|---|---|---|
| 1-2 URL input, normalize, defang | urlnorm.py, scanners.scan_url | r01, r09 |
| 3 submit + poll | api.py /v1/urls/scan, /v1/scans/{id}, store.py | r16 |
| 4-5 engine call + verdict | engines.py, verdict.py | r08, r15 |
| 6 result with reasons/evidence | scanners._pack | r09 |
| 7-8 email input (eml base64/text), parsing | scanners.scan_email, api.py | r10, r16 |
| 9-10 header checks (SPF/DKIM/Reply-To/display-name spoof) | scanners.header_checks | r10 |
| 11 links and attachments | scanners.body_content, attachment_meta | r11 |
| 12 email verdict | verdict.py | r10, r11 |
| SMS Scanner | scanners.scan_sms, /v1/sms/scan | r12 |
| Automatic SMS Protection | /v1/protection/sms (sync + deadline fallback) | r13 |
| 21-24 Secure Browser pre-check | scanners.browser_precheck, /v1/browser/precheck | r14 |
| 25-28 Threat intel (VirusTotal, local blocklist, cache, unavailable never safe) | intel.py | r07 |
| SSRF | ssrf.py, fetcher.py | r03, r04, r17 |
| Redirect re-check | fetcher.trace_redirects | r05 |
| Limits (size, time, rate) | config.py, ratelimit.py | r06, r16 |
| No sensitive data in logs | logsafe.py | r16 |
