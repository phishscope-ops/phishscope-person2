# PhishScope Person 2 Scanner, PHP 8 version

نسخة PHP 8 من خدمة Person 2 (نفس الـ API ونفس قواعد الحكم). من غير أي framework ولا composer. شغالة على أي استضافة PHP مجانية.
Same API and verdict rules as the Python reference in the repo root. No framework, no composer, no database server.

## المتطلبات / Requirements
- PHP 8.1+ (اتجربت على 8.5.8) with extensions: curl, mbstring, pdo_sqlite, openssl. `intl` is NOT needed (punycode is hand written).
- A writable folder for the SQLite file (`P2_DB_PATH`).

## التشغيل / Run
    cd php
    php -S 0.0.0.0:8000 -t public            # dev
    php tests/run.php                        # tests, no network, no phpunit
On Apache/shared hosting: point the document root to `php/public` (`.htaccess` already routes everything to `index.php`). Never expose `src/` or `tests/`.
On Nginx: `try_files $uri /index.php?$query_string;` for the public folder.

## الإعدادات / Settings (environment variables, all optional)
Same names as the Python version: P2_ENGINE_URL_BASE, P2_ENGINE_API_KEY, VT_API_KEY, P2_BLOCKLIST_FILE, P2_API_KEY, P2_RATE_LIMIT, P2_DB_PATH.
If a host cannot set env vars, set them with `SetEnv` in `.htaccess` or `putenv()` at the top of `public/index.php`.

## API (same as Python)
POST /v1/urls/scan, /v1/emails/scan, /v1/sms/scan, /v1/protection/sms, /v1/browser/precheck. GET /v1/scans/{id}, GET /health.
Header `X-API-Key` when P2_API_KEY is set. Optional `client_ref` is echoed back.

## الفرق عن نسخة Python / Differences (honest list)
1. Synchronous: POST returns 202 with `status: "completed"` and the full `result` in the same response. `GET /v1/scans/{id}` still works. No background jobs.
2. IDN: punycode only, no nameprep/UTS46 normalisation (needs `intl`). Odd Unicode hosts may normalise differently from Python.
3. IPv6: only 2000::/3 is treated as public; 6to4 / Teredo / NAT64 / mapped addresses are checked on the embedded IPv4. These rules are ours, not a library's.
4. Remote ML engine adapter is tested with mocks only.
5. Fetching uses curl with the vetted IP pinned (`CURLOPT_RESOLVE`) and every redirect hop re-checked.

## ما اتجربش / Not tested
PHP 7.4 and PHP < 8.1, Apache/FPM/nginx deployments (tested on `php -S` only), real mail corpora, high concurrency or SQLite lock contention, real VirusTotal, real teammate ML engine, any device.
