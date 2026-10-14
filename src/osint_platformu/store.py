"""SQLite storage: investigations, runs, observations (with provenance), raw responses (compressed, de-duplicated by hash) and an HTTP cache."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import zlib

from .model import Obs

SCHEMA = """
CREATE TABLE IF NOT EXISTS investigations (id INTEGER PRIMARY KEY, target TEXT UNIQUE NOT NULL, purpose TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS runs (id INTEGER PRIMARY KEY, investigation_id INTEGER NOT NULL REFERENCES investigations(id), started_at TEXT NOT NULL,
                                 finished_at TEXT, sources TEXT NOT NULL, purpose TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS observations (id INTEGER PRIMARY KEY, run_id INTEGER NOT NULL REFERENCES runs(id), source TEXT NOT NULL, subject TEXT NOT NULL,
                                         predicate TEXT NOT NULL, object TEXT NOT NULL, url TEXT NOT NULL, raw_sha256 TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS obs_run_pred ON observations(run_id, predicate);
CREATE INDEX IF NOT EXISTS obs_run_subject ON observations(run_id, subject);
CREATE TABLE IF NOT EXISTS source_status (run_id INTEGER NOT NULL REFERENCES runs(id), source TEXT NOT NULL, state TEXT NOT NULL, detail TEXT NOT NULL, count INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS raw (sha256 TEXT PRIMARY KEY, size INTEGER NOT NULL, body BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS cache (key TEXT PRIMARY KEY, retrieved REAL NOT NULL, status INTEGER NOT NULL, sha256 TEXT NOT NULL REFERENCES raw(sha256));
"""


class Store:
    def __init__(self, path=":memory:"):
        self.path = path
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock:
            self.db.executescript(SCHEMA)
            self.db.commit()

    def close(self):
        self.db.close()

    # --- raw responses and the HTTP cache -------------------------------------------------------------------------------------------------
    def put_raw(self, body):
        sha = hashlib.sha256(body).hexdigest()
        with self._lock:
            self.db.execute("INSERT OR IGNORE INTO raw (sha256, size, body) VALUES (?, ?, ?)", (sha, len(body), zlib.compress(body, 6)))
            self.db.commit()
        return sha

    def get_raw(self, sha):
        with self._lock:
            row = self.db.execute("SELECT body FROM raw WHERE sha256 = ?", (sha,)).fetchone()
        return zlib.decompress(row["body"]) if row else None

    def cache_put(self, key, status, body, now):
        sha = self.put_raw(body)
        with self._lock:
            self.db.execute("INSERT OR REPLACE INTO cache (key, retrieved, status, sha256) VALUES (?, ?, ?, ?)", (key, now, status, sha))
            self.db.commit()

    def cache_get(self, key, ttl, now=None):
        import time
        now = time.time() if now is None else now
        with self._lock:
            row = self.db.execute("SELECT retrieved, status, sha256 FROM cache WHERE key = ?", (key,)).fetchone()
        if not row or now - row["retrieved"] > ttl:
            return None
        body = self.get_raw(row["sha256"])
        return (row["status"], body) if body is not None else None

    # --- investigations, runs, observations ----------------------------------------------------------------------------------------------
    def investigation(self, target, purpose, created_at):
        with self._lock:
            row = self.db.execute("SELECT id FROM investigations WHERE target = ?", (target,)).fetchone()
            if row:
                return row["id"]
            cur = self.db.execute("INSERT INTO investigations (target, purpose, created_at) VALUES (?, ?, ?)", (target, purpose, created_at))
            self.db.commit()
            return cur.lastrowid

    def start_run(self, investigation_id, sources, purpose, started_at):
        with self._lock:
            cur = self.db.execute("INSERT INTO runs (investigation_id, started_at, sources, purpose) VALUES (?, ?, ?, ?)",
                                  (investigation_id, started_at, json.dumps(sorted(sources)), purpose))
            self.db.commit()
            return cur.lastrowid

    def finish_run(self, run_id, finished_at):
        with self._lock:
            self.db.execute("UPDATE runs SET finished_at = ? WHERE id = ?", (finished_at, run_id))
            self.db.commit()

    def add_observations(self, run_id, observations):
        rows = [(run_id, o.source, o.subject, o.predicate, json.dumps(o.object, sort_keys=True, ensure_ascii=False), o.url, o.raw) for o in observations]
        with self._lock:
            self.db.executemany("INSERT INTO observations (run_id, source, subject, predicate, object, url, raw_sha256) VALUES (?, ?, ?, ?, ?, ?, ?)", rows)
            self.db.commit()

    def add_status(self, run_id, status):
        with self._lock:
            self.db.execute("INSERT INTO source_status (run_id, source, state, detail, count) VALUES (?, ?, ?, ?, ?)",
                            (run_id, status.source, status.state, status.detail, status.count))
            self.db.commit()

    def observations(self, run_id, predicate=None, subject=None):
        sql, args = "SELECT * FROM observations WHERE run_id = ?", [run_id]
        if predicate:
            sql += " AND predicate = ?"
            args.append(predicate)
        if subject:
            sql += " AND subject = ?"
            args.append(subject)
        with self._lock:
            rows = self.db.execute(sql + " ORDER BY id", args).fetchall()
        return [Obs(r["source"], r["subject"], r["predicate"], json.loads(r["object"]), r["url"], r["raw_sha256"]) for r in rows]

    def statuses(self, run_id):
        with self._lock:
            return [dict(r) for r in self.db.execute("SELECT source, state, detail, count FROM source_status WHERE run_id = ? ORDER BY rowid", (run_id,))]

    def runs(self, target):
        with self._lock:
            rows = self.db.execute("SELECT r.id, r.started_at, r.finished_at, r.sources, r.purpose FROM runs r JOIN investigations i ON i.id = r.investigation_id "
                                   "WHERE i.target = ? ORDER BY r.id", (target,)).fetchall()
        return [dict(r) for r in rows]

    def investigations(self):
        with self._lock:
            return [dict(r) for r in self.db.execute("SELECT i.target, i.purpose, i.created_at, COUNT(r.id) AS runs FROM investigations i "
                                                     "LEFT JOIN runs r ON r.investigation_id = i.id GROUP BY i.id ORDER BY i.id")]

    def dump_text(self):
        """All stored text (observations and decompressed raw bodies) as one string: what the privacy tests search."""
        with self._lock:
            parts = [" ".join(map(str, tuple(r))) for r in self.db.execute("SELECT source, subject, predicate, object, url FROM observations")]
            parts += [zlib.decompress(r["body"]).decode("utf-8", "replace") for r in self.db.execute("SELECT body FROM raw")]
        return "\n".join(parts)
