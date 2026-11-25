<?php
declare(strict_types=1);
namespace P2;

/** Scan records and the rate limiter (SQLite through PDO). This is the only place that knows about storage, so the
 *  database teammate can replace it. Stored results hold defanged links and never the raw SMS or email body. */
final class Store
{
    private \PDO $db;

    public function __construct(string $path, private int $ttl = 604800)
    {
        $this->db = new \PDO('sqlite:' . $path);
        $this->db->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
        $this->db->exec('PRAGMA busy_timeout=3000');
        $this->db->exec('CREATE TABLE IF NOT EXISTS scans (id TEXT PRIMARY KEY, kind TEXT, status TEXT, created REAL, updated REAL, result TEXT)');
        $this->db->exec('CREATE TABLE IF NOT EXISTS hits (k TEXT, t REAL)');
        $this->db->exec('CREATE INDEX IF NOT EXISTS hits_k ON hits(k)');
    }

    public static function uuid(): string
    {
        $b = random_bytes(16);
        $b[6] = chr((ord($b[6]) & 0x0f) | 0x40);
        $b[8] = chr((ord($b[8]) & 0x3f) | 0x80);
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($b), 4));
    }

    public function create(string $kind): string
    {
        $id = self::uuid();
        $now = microtime(true);
        $this->db->prepare('INSERT INTO scans VALUES (?,?,?,?,?,NULL)')->execute([$id, $kind, 'queued', $now, $now]);
        $this->db->prepare('DELETE FROM scans WHERE created < ?')->execute([$now - $this->ttl]);
        return $id;
    }

    public function update(string $id, string $status, ?array $result = null): void
    {
        $this->db->prepare('UPDATE scans SET status=?, updated=?, result=? WHERE id=?')
            ->execute([$status, microtime(true), $result === null ? null : json_encode($result, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE), $id]);
    }

    public function get(string $id): ?array
    {
        $st = $this->db->prepare('SELECT id, kind, status, created, updated, result FROM scans WHERE id=?');
        $st->execute([$id]);
        $r = $st->fetch(\PDO::FETCH_NUM);
        if (!$r) return null;
        return ['scan_id' => $r[0], 'kind' => $r[1], 'status' => $r[2], 'created_at' => (float)$r[3], 'updated_at' => (float)$r[4],
            'result' => $r[5] !== null ? json_decode($r[5], true) : null];
    }

    /** Sliding window per client key (security 10). */
    public function allow(string $key, int $perMinute, ?float $now = null): bool
    {
        $now ??= microtime(true);
        $this->db->prepare('DELETE FROM hits WHERE t <= ?')->execute([$now - 60]);
        $st = $this->db->prepare('SELECT COUNT(*) FROM hits WHERE k=?');
        $st->execute([$key]);
        if ((int)$st->fetchColumn() >= $perMinute) return false;
        $this->db->prepare('INSERT INTO hits VALUES (?,?)')->execute([$key, $now]);
        return true;
    }
}
