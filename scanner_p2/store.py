"""Scan records (requirement 6, status tracking). SQLite by default; this file is the only place that knows about
storage, so the database teammate can replace `ScanStore` with a Postgres version without touching anything else.
Stored results hold defanged links and never the raw SMS or email body."""
import json
import sqlite3
import threading
import time
import uuid
from typing import Optional


class ScanStore:
    def __init__(self, path: str, ttl_seconds: int):
        self.ttl = ttl_seconds
        self.lock = threading.Lock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("CREATE TABLE IF NOT EXISTS scans (id TEXT PRIMARY KEY, kind TEXT, status TEXT, created REAL, updated REAL, result TEXT)")
        self.db.commit()

    def create(self, kind: str) -> str:
        sid = str(uuid.uuid4())
        now = time.time()
        with self.lock:
            self.db.execute("INSERT INTO scans VALUES (?,?,?,?,?,?)", (sid, kind, "queued", now, now, None))
            self.db.execute("DELETE FROM scans WHERE created < ?", (now - self.ttl,))
            self.db.commit()
        return sid

    def update(self, sid: str, status: str, result: Optional[dict] = None):
        with self.lock:
            self.db.execute("UPDATE scans SET status=?, updated=?, result=? WHERE id=?",
                            (status, time.time(), json.dumps(result, ensure_ascii=False) if result is not None else None, sid))
            self.db.commit()

    def get(self, sid: str) -> Optional[dict]:
        with self.lock:
            row = self.db.execute("SELECT id, kind, status, created, updated, result FROM scans WHERE id=?", (sid,)).fetchone()
        if not row:
            return None
        return {"scan_id": row[0], "kind": row[1], "status": row[2], "created_at": row[3], "updated_at": row[4],
                "result": json.loads(row[5]) if row[5] else None}
