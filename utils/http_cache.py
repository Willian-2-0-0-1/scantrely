"""
SQLite-backed HTTP response cache shared between pipeline phases.
Reduces duplicate HTTP requests to the same URLs across phases.

Storage: scans/<scan_id>/http_cache.db
TTL: duration of the scan (cache cleared on new scan)
"""

import sqlite3, hashlib, json, time, os
from contextlib import contextmanager
import logging as _logging
_log = _logging.getLogger('scantrely.http_cache')
from pathlib import Path
from typing import Any
from urllib.request import Request


class HttpCache:
    """Thread-safe SQLite cache for HTTP responses during a scan."""

    def __init__(self, db_path: str):
        self._db_path = db_path
        self._init_db()

    @contextmanager
    def _connect(self):
        # o with de sqlite3.Connection não fecha a conexão (vazava descritor); fecha sempre
        conn = sqlite3.connect(self._db_path, timeout=5)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            with conn:
                yield conn
        finally:
            conn.close()

    def _init_db(self):
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS http_cache (
                    method  TEXT NOT NULL,
                    url     TEXT NOT NULL,
                    status  INTEGER,
                    headers TEXT,
                    body_sha256 TEXT,
                    body_path   TEXT,
                    created_at  REAL,
                    PRIMARY KEY (method, url)
                )
            """)
            conn.commit()

    def get(self, method: str, url: str) -> dict | None:
        """Return cached response dict or None."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT status, headers, body_sha256, body_path FROM http_cache WHERE method=? AND url=?",
                (method.upper(), url)
            ).fetchone()
            if not row:
                return None
            status, headers_json, sha, body_path = row
            body = None
            if body_path and os.path.exists(body_path):
                try:
                    with open(body_path, "rb") as f:
                        body = f.read()
                except Exception:
                    _log.debug('http_cache.py:59 erro ignorado', exc_info=True)
            return {
                "status": status,
                "headers": json.loads(headers_json) if headers_json else {},
                "body_sha256": sha,
                "body": body,
            }

    def set(self, method: str, url: str, status: int, headers: dict, body: bytes | None):
        """Store a response in the cache."""
        sha = hashlib.sha256(body or b"").hexdigest()
        body_path = None

        # Bodies > 100KB go to disk, only hash in DB
        if body and len(body) > 102400:
            body_dir = Path(self._db_path).parent / "http_bodies"
            body_dir.mkdir(parents=True, exist_ok=True)
            body_path = str(body_dir / f"{sha}.bin")
            with open(body_path, "wb") as f:
                f.write(body)

        with self._connect() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO http_cache (method, url, status, headers, body_sha256, body_path, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (method.upper(), url, status, json.dumps(dict(headers or {})),
                 sha, body_path, time.time())
            )
            conn.commit()

    def fetch(self, url: str, method: str = "GET", headers: dict | None = None,
              timeout: int = 15, force: bool = False) -> dict:
        """Fetch URL with caching. Returns dict with status, headers, body_sha256, body."""
        if not force:
            cached = self.get(method, url)
            if cached is not None:
                return cached

        req = Request(url, headers=headers or {"User-Agent": "ASM-Platform/1.0"})
        req.method = method.upper()
        from utils.circuit_breaker import CircuitOpen, guarded_urlopen
        try:
            with guarded_urlopen(req, timeout=timeout) as resp:
                resp_headers = dict(resp.headers)
                body = resp.read()
                result = {
                    "status": resp.status,
                    "headers": resp_headers,
                    "body_sha256": hashlib.sha256(body).hexdigest(),
                    "body": body,
                }
                self.set(method, url, resp.status, resp_headers, body)
                return result
        except CircuitOpen:
            return {"status": 0, "headers": {}, "body_sha256": "", "body": None}
        except Exception:
            return {"status": 0, "headers": {}, "body_sha256": "", "body": None}

    def clear(self):
        """Clear all cached entries."""
        with self._connect() as conn:
            conn.execute("DELETE FROM http_cache")
            conn.commit()
