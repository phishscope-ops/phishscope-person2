<?php
// PhishScope Person 2 scanner: PHP cURL client example (PHP 7.4+, needs ext-curl and ext-json).
// Call the scanner from YOUR BACKEND only (never from the mobile app), so the API key stays secret.

const P2_BASE = 'http://localhost:8000';   // the scanner service address
const P2_KEY  = '';                        // same value as P2_API_KEY on the scanner ('' if not set)

function p2_request(string $method, string $path, ?array $body = null): array
{
    $ch = curl_init(P2_BASE . $path);
    $headers = ['Accept: application/json'];
    if (P2_KEY !== '') {
        $headers[] = 'X-API-Key: ' . P2_KEY;
    }
    $opts = [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 15, CURLOPT_CUSTOMREQUEST => $method];
    if ($body !== null) {
        $headers[] = 'Content-Type: application/json';
        $opts[CURLOPT_POSTFIELDS] = json_encode($body, JSON_UNESCAPED_UNICODE);
    }
    $opts[CURLOPT_HTTPHEADER] = $headers;
    curl_setopt_array($ch, $opts);
    $raw = curl_exec($ch);
    $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err = curl_error($ch);
    if ($raw === false) {
        return ['http' => 0, 'data' => null, 'error' => $err];
    }
    return ['http' => $code, 'data' => json_decode($raw, true), 'error' => null];
}

/** 1) create a URL scan. $clientRef = your own scan row id (comes back unchanged). */
function p2_create_url_scan(string $url, string $clientRef): ?string
{
    $r = p2_request('POST', '/v1/urls/scan', ['url' => $url, 'client_ref' => $clientRef]);
    return ($r['http'] === 202) ? $r['data']['scan_id'] : null;   // 401 = bad key, 429 = too many, 422 = bad input
}

/** 2) poll until completed or failed. Returns the result array, or null on timeout. */
function p2_wait_result(string $scanId, int $maxSeconds = 30): ?array
{
    $deadline = time() + $maxSeconds;
    do {
        $r = p2_request('GET', '/v1/scans/' . rawurlencode($scanId));
        if ($r['http'] === 200 && in_array($r['data']['status'], ['completed', 'failed'], true)) {
            return $r['data'];
        }
        sleep(1);
    } while (time() < $deadline);
    return null;   // treat as UNKNOWN, never as safe
}

// ---- usage
if (PHP_SAPI === 'cli' && realpath($argv[0]) === __FILE__) {
    $id = p2_create_url_scan($argv[1] ?? 'https://example.com/', 'scan-1001');
    if ($id === null) { fwrite(STDERR, "could not create scan\n"); exit(1); }
    $scan = p2_wait_result($id);
    if ($scan === null || $scan['status'] !== 'completed') { echo "unknown (no result)\n"; exit(0); }
    $res = $scan['result'];
    // Store what you need: $scan['scan_id'], $res['client_ref'], $res['scanner_verdict'], $res['severity'], $res['risk_score'], $res['evidence_items']
    echo json_encode(['client_ref' => $res['client_ref'], 'scanner_verdict' => $res['scanner_verdict'],
        'severity' => $res['severity'], 'risk_score' => $res['risk_score']], JSON_UNESCAPED_UNICODE), "\n";
}
