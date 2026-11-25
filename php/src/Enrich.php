<?php
declare(strict_types=1);
namespace P2;

/** Hand-off fields for the Risk Engine (Person 3) and history owner (Person 1). Our verdict is a COMPONENT verdict. */
final class Enrich
{
    public static function severity(string $verdict, int $score): string
    {
        if ($verdict === 'unknown') return 'unknown';
        if ($verdict === 'safe') return 'none';
        $base = $score < 30 ? 'low' : ($score < 60 ? 'medium' : ($score < 80 ? 'high' : 'critical'));
        if ($verdict === 'malicious' && in_array($base, ['low', 'medium'], true)) return 'high';
        return $base;
    }

    public static function evidenceItems(array $res): array
    {
        $items = [];
        $ev = $res['evidence'] ?? [];
        foreach ($ev['engine'] ?? [] as $e) $items[] = ['source' => 'engine:' . ($e['engine'] ?? ''), 'type' => 'model_result', 'state' => $e['state'] ?? null, 'label' => $e['label'] ?? null, 'score' => $e['score'] ?? null, 'detail' => $e['reasons'] ?? []];
        foreach ($ev['threat_intel'] ?? [] as $t) $items[] = ['source' => 'intel:' . ($t['provider'] ?? ''), 'type' => 'threat_intel', 'state' => $t['state'] ?? null, 'label' => $t['verdict'] ?? null, 'detail' => $t['detail'] ?? ''];
        if (!empty($ev['redirects'])) {
            $r = $ev['redirects'];
            $items[] = ['source' => 'redirect_trace', 'type' => 'redirects', 'state' => !empty($r['complete']) ? 'complete' : 'incomplete', 'detail' => ['hops' => $r['hop_count'] ?? null, 'chain' => $r['chain_defanged'] ?? [], 'blocked' => $r['blocked_reason'] ?? '']];
        }
        foreach ($res['reasons'] ?? [] as $why) $items[] = ['source' => 'p2_rules', 'type' => 'reason', 'detail' => $why];
        foreach ($res['links'] ?? [] as $l) $items[] = ['source' => 'link', 'type' => 'link_result', 'label' => $l['verdict'] ?? null, 'detail' => $l['url_defanged'] ?? ''];
        return $items;
    }

    public static function apply(array $res, ?string $clientRef = null): array
    {
        $v = $res['verdict'] ?? 'unknown';
        $s = (int)($res['risk_score'] ?? 0);
        $res['severity'] = self::severity($v, $s);
        $res['scanner_verdict'] = $v;  // component verdict; the final verdict is Person 3's
        $res['evidence_items'] = self::evidenceItems($res);
        if ($clientRef !== null) $res['client_ref'] = $clientRef;
        return $res;
    }
}
