#!/usr/bin/env python3
"""
SQLite persistence layer for ASM metadata.

The database becomes the source of truth for operational metadata while
selected legacy JSON files are still mirrored for backward compatibility with
older scripts that read them directly.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from datetime import datetime
from pathlib import Path


class ASMDatabase:
    def __init__(
        self,
        db_path: Path,
        *,
        asm_data_file: Path | None = None,
        snapshots_dir: Path | None = None,
        companies_file: Path | None = None,
        settings_file: Path | None = None,
        admins_file: Path | None = None,
        schedules_file: Path | None = None,
        webhooks_file: Path | None = None,
        whitelist_file: Path | None = None,
        audit_log_file: Path | None = None,
    ):
        self.db_path = Path(db_path)
        self._lock = threading.RLock()
        self.asm_data_file = asm_data_file
        self.snapshots_dir = snapshots_dir
        self.companies_file = companies_file
        self.settings_file = settings_file
        self.admins_file = admins_file
        self.schedules_file = schedules_file
        self.webhooks_file = webhooks_file
        self.whitelist_file = whitelist_file
        self.audit_log_file = audit_log_file

    def initialize(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(
                """
                PRAGMA journal_mode=WAL;
                PRAGMA foreign_keys=ON;
                PRAGMA busy_timeout=5000;

                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS admins (
                    id TEXT PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    email TEXT NOT NULL DEFAULT '',
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL,
                    scoped_companies TEXT NOT NULL DEFAULT '[]',
                    created_at TEXT NOT NULL,
                    last_login TEXT
                );

                CREATE TABLE IF NOT EXISTS companies (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    domains_json TEXT NOT NULL DEFAULT '[]',
                    color TEXT NOT NULL DEFAULT '#00c9a7',
                    tags_json TEXT NOT NULL DEFAULT '[]',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS schedules (
                    company_id TEXT PRIMARY KEY,
                    profile TEXT NOT NULL,
                    interval_hours INTEGER NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 0,
                    next_run TEXT NOT NULL DEFAULT '',
                    last_run TEXT NOT NULL DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS webhooks (
                    id TEXT PRIMARY KEY,
                    type TEXT NOT NULL DEFAULT 'generic',
                    url TEXT NOT NULL DEFAULT '',
                    chat_id TEXT NOT NULL DEFAULT '',
                    events_json TEXT NOT NULL DEFAULT '[]',
                    config_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS whitelist_entries (
                    id TEXT PRIMARY KEY,
                    company_id TEXT NOT NULL,
                    host TEXT NOT NULL DEFAULT '',
                    title TEXT NOT NULL DEFAULT '',
                    reason TEXT NOT NULL DEFAULT '',
                    suppressed_by TEXT NOT NULL DEFAULT '',
                    suppressed_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL,
                    user TEXT NOT NULL,
                    action TEXT NOT NULL,
                    target TEXT NOT NULL DEFAULT '',
                    details TEXT NOT NULL DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS schema_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS scan_stats_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    company_id TEXT NOT NULL,
                    scanned_at TEXT NOT NULL,
                    subdomains INTEGER NOT NULL DEFAULT 0,
                    live_hosts INTEGER NOT NULL DEFAULT 0,
                    findings_critical INTEGER NOT NULL DEFAULT 0,
                    findings_high INTEGER NOT NULL DEFAULT 0,
                    findings_medium INTEGER NOT NULL DEFAULT 0,
                    findings_low INTEGER NOT NULL DEFAULT 0,
                    open_ports INTEGER NOT NULL DEFAULT 0,
                    waf_protected INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS idx_scan_stats_company ON scan_stats_history(company_id, scanned_at DESC);

                CREATE TABLE IF NOT EXISTS alert_rules (
                    id TEXT PRIMARY KEY,
                    company_id TEXT NOT NULL,
                    name TEXT NOT NULL DEFAULT '',
                    rule_type TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    channels_json TEXT NOT NULL DEFAULT '[]',
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_alert_rules_company ON alert_rules(company_id);

                CREATE TABLE IF NOT EXISTS finding_triage (
                    company_id TEXT NOT NULL,
                    finding_key TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'open',
                    note TEXT NOT NULL DEFAULT '',
                    updated_by TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (company_id, finding_key)
                );
                CREATE INDEX IF NOT EXISTS idx_finding_triage_company ON finding_triage(company_id);

                CREATE TABLE IF NOT EXISTS alerts (
                    id TEXT PRIMARY KEY,
                    company_id TEXT NOT NULL,
                    rule_type TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL DEFAULT '',
                    severity TEXT NOT NULL DEFAULT 'info',
                    data_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    read INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS idx_alerts_company ON alerts(company_id, created_at DESC);

                CREATE TABLE IF NOT EXISTS asm_data_state (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    json_text TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS snapshots (
                    company_id TEXT NOT NULL,
                    slot TEXT NOT NULL,
                    ts TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    PRIMARY KEY (company_id, slot)
                );

                CREATE TABLE IF NOT EXISTS subdomain_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    company_id TEXT NOT NULL,
                    subdomain TEXT NOT NULL,
                    event TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    is_alive INTEGER NOT NULL DEFAULT 0,
                    source TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_subhistory_company ON subdomain_history(company_id);
                CREATE INDEX IF NOT EXISTS idx_subhistory_subdomain ON subdomain_history(subdomain);
                CREATE INDEX IF NOT EXISTS idx_subhistory_event ON subdomain_history(event);
                CREATE INDEX IF NOT EXISTS idx_audit_log_ts ON audit_log(ts DESC);
                CREATE INDEX IF NOT EXISTS idx_whitelist_company ON whitelist_entries(company_id);
                CREATE INDEX IF NOT EXISTS idx_webhooks_type ON webhooks(type);
                CREATE INDEX IF NOT EXISTS idx_companies_name ON companies(name COLLATE NOCASE);

                CREATE TABLE IF NOT EXISTS sessions (
                    token      TEXT PRIMARY KEY,
                    data_json  TEXT NOT NULL,
                    expires_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

                CREATE TABLE IF NOT EXISTS tool_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    company_id TEXT NOT NULL DEFAULT '',
                    module TEXT NOT NULL DEFAULT '',
                    tool TEXT NOT NULL,
                    argv_json TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'running',
                    exit_code INTEGER,
                    duration REAL NOT NULL DEFAULT 0,
                    stdout_tail TEXT NOT NULL DEFAULT '',
                    stderr_tail TEXT NOT NULL DEFAULT '',
                    started_at TEXT NOT NULL,
                    finished_at TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_tool_runs_company ON tool_runs(company_id, started_at DESC);
                CREATE INDEX IF NOT EXISTS idx_tool_runs_tool ON tool_runs(tool, started_at DESC);

                CREATE TABLE IF NOT EXISTS jobs (
                    id TEXT PRIMARY KEY,
                    job_type TEXT NOT NULL,
                    company_id TEXT NOT NULL DEFAULT '',
                    target TEXT NOT NULL DEFAULT '',
                    options_json TEXT NOT NULL DEFAULT '{}',
                    status TEXT NOT NULL DEFAULT 'pending',
                    priority INTEGER NOT NULL DEFAULT 100,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    max_attempts INTEGER NOT NULL DEFAULT 1,
                    created_by TEXT NOT NULL DEFAULT '',
                    error TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    started_at TEXT,
                    finished_at TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_jobs_status_priority ON jobs(status, priority, created_at);
                CREATE INDEX IF NOT EXISTS idx_jobs_company ON jobs(company_id, created_at DESC);
                """
            )
            conn.execute(
                """
                INSERT INTO schema_meta (key, value)
                VALUES ('schema_version', '2')
                ON CONFLICT(key) DO UPDATE SET value='2'
                """
            )
            # Migration v2 → v3: add scoped_companies to admins
            try:
                conn.execute("ALTER TABLE admins ADD COLUMN scoped_companies TEXT NOT NULL DEFAULT '[]'")
            except Exception:
                pass  # column already exists
            # Migration v3 → v4: add name to alert_rules
            try:
                conn.execute("ALTER TABLE alert_rules ADD COLUMN name TEXT NOT NULL DEFAULT ''")
            except Exception:
                pass  # column already exists
            conn.commit()

    def migrate_from_legacy(self) -> None:
        with self._lock:
            self._migrate_settings()
            self._migrate_admins()
            self._migrate_companies()
            self._migrate_schedules()
            self._migrate_webhooks()
            self._migrate_whitelist()
            self._migrate_audit_log()
            self._migrate_asm_data()
            self._migrate_snapshots()
            self.sync_legacy_files()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    _VALID_TABLES = frozenset({
        "settings", "admins", "companies", "schedules", "webhooks",
        "whitelist_entries", "audit_log", "asm_data_state", "snapshots",
        "subdomain_history", "scan_stats_history", "alert_rules", "alerts",
        "tool_runs", "jobs", "finding_triage",
    })

    def _table_count(self, table: str) -> int:
        if table not in self._VALID_TABLES:
            raise ValueError(f"Invalid table name: {table!r}")
        with self._connect() as conn:
            row = conn.execute(f"SELECT COUNT(*) AS count FROM {table}").fetchone()
            return int(row["count"])

    @staticmethod
    def _now() -> str:
        return datetime.now().isoformat(timespec="seconds")

    @staticmethod
    def _json_dumps(value) -> str:
        return json.dumps(value, ensure_ascii=False)

    @staticmethod
    def _json_loads(value: str, default):
        try:
            return json.loads(value)
        except Exception:
            return default

    # ─── Session persistence ───────────────────────────────────────────────────

    def load_sessions(self) -> dict[str, dict]:
        """Return {token: session_dict} for all non-expired sessions."""
        import time
        now = time.time()
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT token, data_json FROM sessions WHERE expires_at > ?", (now,)
            ).fetchall()
        result = {}
        for row in rows:
            try:
                data = json.loads(row["data_json"])
                result[row["token"]] = data
            except Exception:
                pass
        return result

    def save_session(self, token: str, data: dict) -> None:
        expires_at = data.get("expires_at", 0.0)
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO sessions (token, data_json, expires_at) VALUES (?,?,?)",
                (token, json.dumps(data), expires_at),
            )
            conn.commit()

    def delete_session(self, token: str) -> None:
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM sessions WHERE token=?", (token,))
            conn.commit()

    def purge_expired_sessions(self) -> None:
        import time
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (time.time(),))
            conn.commit()

    def _read_json_file(self, path: Path | None, default):
        if not path or not path.exists():
            return default
        try:
            return json.loads(path.read_text())
        except Exception:
            return default

    def _migrate_settings(self) -> None:
        data = self._read_json_file(self.settings_file, {})
        if not isinstance(data, dict) or not data:
            # Primary settings file missing/empty (e.g. accidental delete) —
            # recover from the redundant backup copy if present.
            if self.settings_file:
                backup = self.settings_file.with_name(self.settings_file.stem + ".backup.json")
                backup_data = self._read_json_file(backup, {})
                if isinstance(backup_data, dict):
                    data = backup_data
        if not isinstance(data, dict):
            return
        existing = self.get_settings()
        merged = {**data, **existing}
        if merged:
            self.set_settings(merged)

    def _migrate_admins(self) -> None:
        if self._table_count("admins") > 0:
            return
        payload = self._read_json_file(self.admins_file, {})
        admins = payload.get("admins", []) if isinstance(payload, dict) else []
        if admins:
            self.save_admins(admins)

    def _migrate_companies(self) -> None:
        payload = self._read_json_file(self.companies_file, {})
        companies = payload.get("companies", []) if isinstance(payload, dict) else []
        if self._table_count("companies") == 0 and companies:
            self.save_companies(companies)
            return
        if self._table_count("companies") > 0:
            current = self.load_companies()
            if current:
                self._sync_asm_data_companies(current)

    def _migrate_schedules(self) -> None:
        if self._table_count("schedules") > 0:
            return
        schedules = self._read_json_file(self.schedules_file, {})
        if isinstance(schedules, dict) and schedules:
            self.save_schedules(schedules)

    def _migrate_webhooks(self) -> None:
        if self._table_count("webhooks") > 0:
            return
        hooks = self._read_json_file(self.webhooks_file, [])
        if isinstance(hooks, list) and hooks:
            self.save_webhooks(hooks)

    def _migrate_whitelist(self) -> None:
        if self._table_count("whitelist_entries") > 0:
            return
        data = self._read_json_file(self.whitelist_file, {})
        if isinstance(data, dict) and data:
            self.save_whitelist(data)

    def _migrate_audit_log(self) -> None:
        if self._table_count("audit_log") > 0 or not self.audit_log_file or not self.audit_log_file.exists():
            return
        entries = []
        for line in self.audit_log_file.read_text().splitlines():
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except Exception:
                continue
            entries.append(
                {
                    "ts": item.get("ts", self._now()),
                    "user": item.get("user", "system"),
                    "action": item.get("action", ""),
                    "target": item.get("target", ""),
                    "details": item.get("details", ""),
                }
            )
        if not entries:
            return
        with self._connect() as conn:
            conn.executemany(
                "INSERT INTO audit_log (ts, user, action, target, details) VALUES (?, ?, ?, ?, ?)",
                [(e["ts"], e["user"], e["action"], e["target"], e["details"]) for e in entries],
            )
            conn.commit()

    def _migrate_asm_data(self) -> None:
        if self._table_count("asm_data_state") > 0:
            return
        if self.asm_data_file and self.asm_data_file.exists():
            try:
                text = self.asm_data_file.read_text()
                data = json.loads(text.removeprefix("window.ASM_DATA = ").rstrip(";\n"))
            except Exception:
                data = {"version": "1.0", "generated": "", "companies": []}
        else:
            data = {"version": "1.0", "generated": "", "companies": []}
        self.save_asm_data(data)

    def _migrate_snapshots(self) -> None:
        if self._table_count("snapshots") > 0 or not self.snapshots_dir or not self.snapshots_dir.exists():
            return
        for path in self.snapshots_dir.glob("*.json"):
            name = path.stem
            slot = "current"
            company_id = name
            if name.endswith("_prev"):
                company_id = name[:-5]
                slot = "previous"
            try:
                payload = json.loads(path.read_text())
            except Exception:
                continue
            self.save_snapshot(company_id, payload, slot=slot)

    def get_settings(self, keys: set[str] | None = None) -> dict[str, str]:
        with self._connect() as conn:
            rows = conn.execute("SELECT key, value FROM settings ORDER BY key").fetchall()
        data = {row["key"]: row["value"] for row in rows}
        if keys is None:
            return data
        return {key: data.get(key, "") for key in keys}

    def set_settings(self, values: dict[str, str]) -> None:
        now = self._now()
        with self._lock, self._connect() as conn:
            conn.executemany(
                """
                INSERT INTO settings (key, value, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    value=excluded.value,
                    updated_at=excluded.updated_at
                """,
                [(key, str(value), now) for key, value in values.items()],
            )
            conn.commit()
        self._sync_settings_file()

    def load_admins(self) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, username, email, password_hash, role, scoped_companies, created_at, last_login
                FROM admins
                ORDER BY created_at, username
                """
            ).fetchall()
        result = []
        for row in rows:
            admin = dict(row)
            admin["scoped_companies"] = self._json_loads(admin.get("scoped_companies", "[]"), [])
            result.append(admin)
        return result

    def save_admins(self, admins: list[dict]) -> None:
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM admins")
            conn.executemany(
                """
                INSERT INTO admins (id, username, email, password_hash, role, scoped_companies, created_at, last_login)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        admin["id"],
                        admin["username"],
                        admin.get("email", ""),
                        admin["password_hash"],
                        admin["role"],
                        self._json_dumps(admin.get("scoped_companies", [])),
                        admin.get("created_at", self._now()),
                        admin.get("last_login"),
                    )
                    for admin in admins
                ],
            )
            conn.commit()
        self._sync_admins_file()

    def delete_company_data(self, cid: str) -> None:
        """Remove every trace of a company from SQLite and the asm_data_state blob."""
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM companies WHERE id = ?", (cid,))
            for table in (
                "schedules", "whitelist_entries",
                "scan_stats_history", "alert_rules", "alerts",
                "snapshots", "subdomain_history", "tool_runs", "jobs",
            ):
                conn.execute(f"DELETE FROM {table} WHERE company_id = ?", (cid,))
            conn.commit()

        self._sync_companies_file()

        data = self.load_asm_data()
        data["companies"] = [c for c in data.get("companies", []) if c.get("id") != cid]
        self.save_asm_data(data)

    def reset_company_scan_data(self, cid: str) -> dict:
        """Reset a company to a freshly-created project state.

        The company record itself is preserved (id/name/domains/color/tags), but
        every scan-derived table row and every derived field in asm_data_state is
        removed. This backs the UI "Clear Data" action: it should not delete the
        project, but after it runs the project must look empty.
        """
        deleted: dict[str, int] = {}
        with self._lock, self._connect() as conn:
            for table in (
                "jobs",
                "tool_runs",
                "snapshots",
                "subdomain_history",
                "scan_stats_history",
                "alerts",
                "alert_rules",
                "schedules",
                "whitelist_entries",
            ):
                cur = conn.execute(f"DELETE FROM {table} WHERE company_id = ?", (cid,))
                deleted[table] = int(cur.rowcount or 0)
            conn.commit()

        data = self.load_asm_data()
        reset = False
        for idx, co in enumerate(data.get("companies", [])):
            if co.get("id") != cid:
                continue
            data["companies"][idx] = {
                "id": co.get("id", cid),
                "name": co.get("name", cid),
                "domains": co.get("domains", []),
                "color": co.get("color", "#3b82f6"),
                "tags": co.get("tags", []),
            }
            reset = True
            break
        if reset:
            self.save_asm_data(data)
        self._sync_snapshots_dir()
        self._sync_schedules_file()
        self._sync_whitelist_file()
        return deleted

    def load_companies(self) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, name, domains_json, color, tags_json
                FROM companies
                ORDER BY name COLLATE NOCASE
                """
            ).fetchall()
        result = []
        for row in rows:
            result.append(
                {
                    "id": row["id"],
                    "name": row["name"],
                    "domains": self._json_loads(row["domains_json"], []),
                    "color": row["color"],
                    "tags": self._json_loads(row["tags_json"], []),
                }
            )
        return result

    def save_companies(self, companies: list[dict]) -> None:
        now = self._now()
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM companies")
            conn.executemany(
                """
                INSERT INTO companies (id, name, domains_json, color, tags_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        company["id"],
                        company["name"],
                        self._json_dumps(company.get("domains", [])),
                        company.get("color", "#00c9a7"),
                        self._json_dumps(company.get("tags", [])),
                        company.get("created_at", now),
                        company.get("updated_at", now),
                    )
                    for company in companies
                ],
            )
            conn.commit()
        self._sync_companies_file()
        self._sync_asm_data_companies(companies)

    def _sync_asm_data_companies(self, companies: list[dict]) -> None:
        """Keep asm_data_state aligned with the canonical companies table."""
        data = self.load_asm_data()
        existing = {
            co.get("id"): co
            for co in data.get("companies", [])
            if isinstance(co, dict) and co.get("id")
        }
        merged = []
        for company in companies:
            cid = company.get("id")
            if not cid:
                continue
            base = dict(existing.get(cid, {}))
            base.update({
                "id": cid,
                "name": company.get("name", base.get("name", "")),
                "domains": company.get("domains", base.get("domains", [])),
                "color": company.get("color", base.get("color", "#00c9a7")),
                "tags": company.get("tags", base.get("tags", [])),
                "created_at": company.get("created_at", base.get("created_at", self._now())),
                "updated_at": company.get("updated_at", base.get("updated_at", self._now())),
            })
            base.setdefault("hosts", existing.get(cid, {}).get("hosts", []))
            base.setdefault("stats", existing.get(cid, {}).get("stats", {}))
            merged.append(base)
        data["companies"] = merged
        data.setdefault("version", "1.0")
        data.setdefault("generated", self._now())
        self.save_asm_data(data)

    def load_schedules(self) -> dict[str, dict]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT company_id, profile, interval_hours, enabled, next_run, last_run
                FROM schedules
                """
            ).fetchall()
        return {
            row["company_id"]: {
                "profile": row["profile"],
                "interval_hours": row["interval_hours"],
                "enabled": bool(row["enabled"]),
                "next_run": row["next_run"],
                "last_run": row["last_run"],
            }
            for row in rows
        }

    def save_schedules(self, schedules: dict[str, dict]) -> None:
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM schedules")
            conn.executemany(
                """
                INSERT INTO schedules (company_id, profile, interval_hours, enabled, next_run, last_run)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        company_id,
                        cfg.get("profile", "standard"),
                        int(cfg.get("interval_hours", 24)),
                        1 if cfg.get("enabled", False) else 0,
                        cfg.get("next_run", ""),
                        cfg.get("last_run", ""),
                    )
                    for company_id, cfg in schedules.items()
                ],
            )
            conn.commit()
        self._sync_schedules_file()

    def load_webhooks(self) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, type, url, chat_id, events_json, config_json
                FROM webhooks
                ORDER BY created_at, id
                """
            ).fetchall()
        hooks = []
        for row in rows:
            base = self._json_loads(row["config_json"], {})
            base.update(
                {
                    "id": row["id"],
                    "type": row["type"],
                    "url": row["url"],
                    "chat_id": row["chat_id"],
                    "events": self._json_loads(row["events_json"], []),
                }
            )
            hooks.append(base)
        return hooks

    def save_webhooks(self, hooks: list[dict]) -> None:
        now = self._now()
        payload = []
        for hook in hooks:
            hook_id = hook.get("id") or uuid.uuid4().hex[:8]
            config = {k: v for k, v in hook.items() if k not in {"id", "type", "url", "chat_id", "events"}}
            payload.append(
                (
                    hook_id,
                    hook.get("type", "generic"),
                    hook.get("url", ""),
                    hook.get("chat_id", ""),
                    self._json_dumps(hook.get("events", [])),
                    self._json_dumps(config),
                    now,
                    now,
                )
            )
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM webhooks")
            conn.executemany(
                """
                INSERT INTO webhooks (id, type, url, chat_id, events_json, config_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                payload,
            )
            conn.commit()
        self._sync_webhooks_file()

    def load_whitelist(self) -> dict[str, list[dict]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, company_id, host, title, reason, suppressed_by, suppressed_at
                FROM whitelist_entries
                ORDER BY suppressed_at DESC
                """
            ).fetchall()
        data: dict[str, list[dict]] = {}
        for row in rows:
            data.setdefault(row["company_id"], []).append(
                {
                    "id": row["id"],
                    "host": row["host"],
                    "title": row["title"],
                    "reason": row["reason"],
                    "suppressed_by": row["suppressed_by"],
                    "suppressed_at": row["suppressed_at"],
                }
            )
        return data

    def save_whitelist(self, whitelist: dict[str, list[dict]]) -> None:
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM whitelist_entries")
            rows = []
            for company_id, entries in whitelist.items():
                for entry in entries:
                    rows.append(
                        (
                            entry.get("id") or uuid.uuid4().hex[:8],
                            company_id,
                            entry.get("host", ""),
                            entry.get("title", ""),
                            entry.get("reason", ""),
                            entry.get("suppressed_by", ""),
                            entry.get("suppressed_at", self._now()),
                        )
                    )
            conn.executemany(
                """
                INSERT INTO whitelist_entries
                (id, company_id, host, title, reason, suppressed_by, suppressed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
            conn.commit()
        self._sync_whitelist_file()

    def append_audit_log(self, entry: dict[str, str]) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO audit_log (ts, user, action, target, details)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    entry.get("ts", self._now()),
                    entry.get("user", "system"),
                    entry.get("action", ""),
                    entry.get("target", ""),
                    entry.get("details", ""),
                ),
            )
            overflow = conn.execute("SELECT COUNT(*) AS count FROM audit_log").fetchone()["count"] - 5000
            if overflow > 0:
                conn.execute(
                    """
                    DELETE FROM audit_log
                    WHERE id IN (
                        SELECT id FROM audit_log ORDER BY id ASC LIMIT ?
                    )
                    """,
                    (overflow,),
                )
            conn.commit()
        self._sync_audit_log_file()

    def list_audit_log(self, limit: int = 200) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT ts, user, action, target, details
                FROM audit_log
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def start_tool_run(self, *, company_id: str = "", module: str = "", tool: str, argv: list[str]) -> int:
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO tool_runs
                (company_id, module, tool, argv_json, status, started_at)
                VALUES (?, ?, ?, ?, 'running', ?)
                """,
                (company_id or "", module or "", tool, self._json_dumps(argv), self._now()),
            )
            conn.commit()
            return int(cur.lastrowid)

    def finish_tool_run(
        self,
        run_id: int,
        *,
        status: str,
        exit_code: int | None,
        duration: float,
        stdout_tail: str = "",
        stderr_tail: str = "",
    ) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                UPDATE tool_runs
                SET status = ?, exit_code = ?, duration = ?, stdout_tail = ?,
                    stderr_tail = ?, finished_at = ?
                WHERE id = ?
                """,
                (status, exit_code, float(duration), stdout_tail or "", stderr_tail or "", self._now(), run_id),
            )
            conn.commit()

    def list_tool_runs(self, company_id: str = "", limit: int = 200) -> list[dict]:
        limit = max(1, min(int(limit), 1000))
        with self._connect() as conn:
            if company_id:
                rows = conn.execute(
                    """
                    SELECT id, company_id, module, tool, argv_json, status, exit_code,
                           duration, stdout_tail, stderr_tail, started_at, finished_at
                    FROM tool_runs
                    WHERE company_id = ?
                    ORDER BY id DESC
                    LIMIT ?
                    """,
                    (company_id, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT id, company_id, module, tool, argv_json, status, exit_code,
                           duration, stdout_tail, stderr_tail, started_at, finished_at
                    FROM tool_runs
                    ORDER BY id DESC
                    LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
        out = []
        for row in rows:
            item = dict(row)
            item["argv"] = self._json_loads(item.pop("argv_json", "[]"), [])
            out.append(item)
        return out

    def latest_tool_run(self, company_id: str, module: str) -> dict | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT id, company_id, module, tool, argv_json, status, exit_code,
                       duration, stdout_tail, stderr_tail, started_at, finished_at
                FROM tool_runs
                WHERE company_id = ?
                  AND module = ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (company_id, module),
            ).fetchone()
        if not row:
            return None
        item = dict(row)
        item["argv"] = self._json_loads(item.pop("argv_json", "[]"), [])
        return item

    def recent_finished_pipeline_jobs(self, company_id: str, target: str, *, limit: int = 20) -> list[dict]:
        limit = max(1, min(int(limit), 100))
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, job_type, company_id, target, options_json, status,
                       priority, attempts, max_attempts, created_by, error,
                       created_at, updated_at, started_at, finished_at
                FROM jobs
                WHERE company_id = ?
                  AND target = ?
                  AND job_type = 'pipeline'
                  AND status = 'done'
                ORDER BY finished_at DESC, updated_at DESC
                LIMIT ?
                """,
                (company_id, target, limit),
            ).fetchall()
        return [self._job_from_row(row) for row in rows]

    def clear_tool_runs(self, company_id: str = "") -> int:
        with self._lock, self._connect() as conn:
            if company_id:
                cur = conn.execute("DELETE FROM tool_runs WHERE company_id = ?", (company_id,))
            else:
                cur = conn.execute("DELETE FROM tool_runs")
            conn.commit()
            return int(cur.rowcount or 0)

    # ─── Persistent job queue ─────────────────────────────────────────────────

    def _job_from_row(self, row) -> dict:
        item = dict(row)
        item["options"] = self._json_loads(item.pop("options_json", "{}"), {})
        return item

    def create_job(
        self,
        *,
        job_type: str,
        company_id: str = "",
        target: str = "",
        options: dict | None = None,
        priority: int = 100,
        created_by: str = "",
        max_attempts: int = 1,
        job_id: str | None = None,
    ) -> dict:
        now = self._now()
        job_id = job_id or uuid.uuid4().hex
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO jobs
                (id, job_type, company_id, target, options_json, status, priority,
                 attempts, max_attempts, created_by, error, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, 'pending', ?, 0, ?, ?, '', ?, ?)
                """,
                (
                    job_id,
                    job_type,
                    company_id or "",
                    target or "",
                    self._json_dumps(options or {}),
                    int(priority),
                    int(max_attempts),
                    created_by or "",
                    now,
                    now,
                ),
            )
            conn.commit()
        return self.get_job(job_id)

    def create_jobs_bulk(self, jobs: list[dict]) -> list[dict]:
        if not jobs:
            return []
        now = self._now()
        rows = []
        out = []
        for job in jobs:
            job_id = job.get("id") or uuid.uuid4().hex
            item = {
                "id": job_id,
                "job_type": job.get("job_type", "pipeline"),
                "company_id": job.get("company_id", ""),
                "target": job.get("target", ""),
                "options": dict(job.get("options") or {}),
                "status": "pending",
                "priority": int(job.get("priority", 100)),
                "attempts": 0,
                "max_attempts": int(job.get("max_attempts", 1)),
                "created_by": job.get("created_by", ""),
                "error": "",
                "created_at": now,
                "updated_at": now,
                "started_at": None,
                "finished_at": None,
            }
            out.append(item)
            rows.append(
                (
                    item["id"],
                    item["job_type"],
                    item["company_id"],
                    item["target"],
                    self._json_dumps(item["options"]),
                    item["status"],
                    item["priority"],
                    item["attempts"],
                    item["max_attempts"],
                    item["created_by"],
                    item["error"],
                    item["created_at"],
                    item["updated_at"],
                )
            )
        with self._lock, self._connect() as conn:
            conn.executemany(
                """
                INSERT INTO jobs
                (id, job_type, company_id, target, options_json, status, priority,
                 attempts, max_attempts, created_by, error, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
            conn.commit()
        return out

    def get_job(self, job_id: str) -> dict | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT id, job_type, company_id, target, options_json, status,
                       priority, attempts, max_attempts, created_by, error,
                       created_at, updated_at, started_at, finished_at
                FROM jobs
                WHERE id = ?
                """,
                (job_id,),
            ).fetchone()
        return self._job_from_row(row) if row else None

    def find_active_job(
        self,
        *,
        company_id: str,
        job_type: str = "pipeline",
        target: str = "",
    ) -> dict | None:
        clauses = ["company_id = ?", "job_type = ?", "status IN ('pending', 'running')"]
        params: list = [company_id, job_type]
        if target:
            clauses.append("target = ?")
            params.append(target)
        with self._lock, self._connect() as conn:
            row = conn.execute(
                """
                SELECT id, job_type, company_id, target, options_json, status,
                       priority, attempts, max_attempts, created_by, error,
                       created_at, updated_at, started_at, finished_at
                FROM jobs
                WHERE {where}
                ORDER BY created_at ASC
                LIMIT 1
                """.format(where=" AND ".join(clauses)),
                tuple(params),
            ).fetchone()
        return self._job_from_row(row) if row else None

    def list_active_job_targets(self, *, company_id: str, job_type: str = "pipeline") -> set[str]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT target
                FROM jobs
                WHERE company_id = ?
                  AND job_type = ?
                  AND status IN ('pending', 'running')
                """,
                (company_id, job_type),
            ).fetchall()
        return {str(row["target"] or "") for row in rows if str(row["target"] or "").strip()}

    def claim_next_job(self) -> dict | None:
        now = self._now()
        with self._lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                """
                SELECT id, job_type, company_id, target, options_json, status,
                       priority, attempts, max_attempts, created_by, error,
                       created_at, updated_at, started_at, finished_at
                FROM jobs
                WHERE status = 'pending'
                ORDER BY priority ASC, created_at ASC
                LIMIT 1
                """
            ).fetchone()
            if not row:
                conn.commit()
                return None
            conn.execute(
                """
                UPDATE jobs
                SET status = 'running',
                    attempts = attempts + 1,
                    started_at = COALESCE(started_at, ?),
                    updated_at = ?
                WHERE id = ? AND status = 'pending'
                """,
                (now, now, row["id"]),
            )
            conn.commit()
        return self.get_job(row["id"])

    def finish_job(self, job_id: str, *, status: str, error: str = "") -> None:
        if status not in {"done", "error", "cancelled"}:
            raise ValueError(f"Invalid final job status: {status!r}")
        now = self._now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                UPDATE jobs
                SET status = ?, error = ?, finished_at = ?, updated_at = ?
                WHERE id = ?
                """,
                (status, (error or "")[:4000], now, now, job_id),
            )
            conn.commit()

    def cancel_job(self, job_id: str, *, reason: str = "cancelled") -> bool:
        now = self._now()
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                """
                UPDATE jobs
                SET status = 'cancelled', error = ?, finished_at = ?, updated_at = ?
                WHERE id = ? AND status = 'pending'
                """,
                ((reason or "cancelled")[:4000], now, now, job_id),
            )
            conn.commit()
            return cur.rowcount > 0

    def delete_job(self, job_id: str) -> bool:
        with self._lock, self._connect() as conn:
            cur = conn.execute("DELETE FROM jobs WHERE id = ?", (job_id,))
            conn.commit()
            return cur.rowcount > 0

    def delete_jobs(
        self,
        *,
        company_id: str = "",
        status: str = "",
        job_type: str = "",
        target: str = "",
    ) -> int:
        clauses = []
        params: list = []
        if company_id:
            clauses.append("company_id = ?")
            params.append(company_id)
        if status:
            clauses.append("status = ?")
            params.append(status)
        if job_type:
            clauses.append("job_type = ?")
            params.append(job_type)
        if target:
            clauses.append("target LIKE ? ESCAPE '\\'")
            esc = target.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            params.append(f"%{esc}%")
        where = "WHERE " + " AND ".join(clauses) if clauses else ""
        with self._lock, self._connect() as conn:
            cur = conn.execute(f"DELETE FROM jobs {where}", tuple(params))
            conn.commit()
            return int(cur.rowcount or 0)

    def cancel_pending_jobs(self, *, company_id: str, job_type: str = "pipeline") -> int:
        now = self._now()
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                """
                UPDATE jobs
                SET status = 'cancelled',
                    error = ?,
                    finished_at = ?,
                    updated_at = ?
                WHERE company_id = ?
                  AND job_type = ?
                  AND status = 'pending'
                """,
                ("cancelled by user", now, now, company_id, job_type),
            )
            conn.commit()
        return int(cur.rowcount or 0)

    def cancel_all_pending_jobs(self) -> int:
        now = self._now()
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                """
                UPDATE jobs
                SET status = 'cancelled',
                    error = ?,
                    finished_at = ?,
                    updated_at = ?
                WHERE status IN ('pending', 'running')
                """,
                ("cancelled by user (cancel all)", now, now),
            )
            conn.commit()
        return int(cur.rowcount or 0)

    def safety_hold_jobs(
        self,
        *,
        reason: str,
        company_id: str = "",
        job_type: str = "pipeline",
    ) -> int:
        """Move pending/running jobs to stopped for host safety.

        This is intentionally stronger than cancel_pending_jobs(): a watchdog
        must be able to stop the queue even when workers already claimed jobs.
        Running pipeline code checks pipeline_state between modules and exits
        cooperatively; pending jobs will not be claimed after this update.
        """
        now = self._now()
        clauses = ["job_type = ?", "status IN ('pending', 'running')"]
        params: list = [job_type]
        if company_id:
            clauses.append("company_id = ?")
            params.append(company_id)
        params.extend([(reason or "safety hold")[:4000], now])
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                f"""
                UPDATE jobs
                SET status = 'stopped',
                    error = ?,
                    updated_at = ?
                WHERE {' AND '.join(clauses)}
                """,
                tuple(params),
            )
            conn.commit()
        return int(cur.rowcount or 0)

    def list_jobs(
        self,
        *,
        company_id: str = "",
        status: str = "",
        job_type: str = "",
        target: str = "",
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict]:
        limit = max(1, min(int(limit), 500))
        offset = max(0, int(offset or 0))
        clauses = []
        params: list = []
        if company_id:
            clauses.append("company_id = ?")
            params.append(company_id)
        if status:
            clauses.append("status = ?")
            params.append(status)
        if job_type:
            clauses.append("job_type = ?")
            params.append(job_type)
        if target:
            # Substring match on the per-domain target (drill-down search).
            clauses.append("target LIKE ? ESCAPE '\\'")
            esc = target.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            params.append(f"%{esc}%")
        where = "WHERE " + " AND ".join(clauses) if clauses else ""
        params.extend([limit, offset])
        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT id, job_type, company_id, target, options_json, status,
                       priority, attempts, max_attempts, created_by, error,
                       created_at, updated_at, started_at, finished_at
                FROM jobs
                {where}
                ORDER BY
                    CASE status
                        WHEN 'running' THEN 0
                        WHEN 'pending' THEN 1
                        ELSE 2
                    END,
                    priority ASC,
                    created_at DESC
                LIMIT ? OFFSET ?
                """,
                tuple(params),
            ).fetchall()
        return [self._job_from_row(row) for row in rows]

    def count_jobs(
        self,
        *,
        company_id: str = "",
        status: str = "",
        job_type: str = "",
        target: str = "",
    ) -> int:
        clauses = []
        params: list = []
        if company_id:
            clauses.append("company_id = ?")
            params.append(company_id)
        if status:
            clauses.append("status = ?")
            params.append(status)
        if job_type:
            clauses.append("job_type = ?")
            params.append(job_type)
        if target:
            clauses.append("target LIKE ? ESCAPE '\\'")
            esc = target.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            params.append(f"%{esc}%")
        where = "WHERE " + " AND ".join(clauses) if clauses else ""
        with self._connect() as conn:
            row = conn.execute(f"SELECT COUNT(*) AS n FROM jobs {where}", tuple(params)).fetchone()
        return int(row["n"] if row else 0)

    def job_company_summary(self) -> list[dict]:
        """Aggregate job counts per company+status without shipping every row.

        Scales to tens of thousands of queued per-domain jobs (the UI groups
        these into one card per company instead of one table row per job).
        """
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT company_id,
                       status,
                       COUNT(*)        AS n,
                       MIN(created_at) AS first_created,
                       MAX(updated_at) AS last_updated
                FROM jobs
                GROUP BY company_id, status
                """
            ).fetchall()
        summary: dict[str, dict] = {}
        for row in rows:
            cid = row["company_id"] or ""
            entry = summary.setdefault(cid, {
                "company_id": cid, "counts": {}, "total": 0,
                "first_created": None, "last_updated": None,
            })
            entry["counts"][row["status"]] = int(row["n"])
            entry["total"] += int(row["n"])
            fc, lu = row["first_created"], row["last_updated"]
            if fc and (entry["first_created"] is None or fc < entry["first_created"]):
                entry["first_created"] = fc
            if lu and (entry["last_updated"] is None or lu > entry["last_updated"]):
                entry["last_updated"] = lu
        return sorted(summary.values(), key=lambda e: e["company_id"])

    def recover_running_jobs(self) -> int:
        """Safely recover interrupted running jobs during server startup.

        Older behavior moved every running job back to pending. On large bug
        bounty queues that can resurrect stale full-scope/active jobs on boot
        and immediately overload the host. Default to stopped; operators can
        deliberately opt into requeue with ASM_RECOVER_RUNNING_TO_PENDING=1.
        """
        now = self._now()
        recover_to_pending = os.environ.get("ASM_RECOVER_RUNNING_TO_PENDING", "0") == "1"
        status = "pending" if recover_to_pending else "stopped"
        error = "Recovered after worker restart" if recover_to_pending else "Stopped after worker restart"
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                """
                UPDATE jobs
                SET status = ?,
                    error = ?,
                    updated_at = ?
                WHERE status = 'running'
                """,
                (status, error, now),
            )
            conn.commit()
            return cur.rowcount

    def get_schema_version(self) -> int:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT value FROM schema_meta WHERE key='schema_version'"
            ).fetchone()
        return int(row["value"]) if row else 0

    def load_asm_data(self) -> dict:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT json_text FROM asm_data_state WHERE id = 1"
            ).fetchone()
        if not row:
            return {"version": "1.0", "generated": "", "companies": []}
        return self._json_loads(row["json_text"], {"version": "1.0", "generated": "", "companies": []})

    def save_asm_data(self, data: dict) -> None:
        now = self._now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO asm_data_state (id, json_text, updated_at)
                VALUES (1, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    json_text=excluded.json_text,
                    updated_at=excluded.updated_at
                """,
                (self._json_dumps(data), now),
            )
            conn.commit()
        self._sync_asm_data_file()

    def import_asm_data_file(self, path: Path | None = None) -> dict:
        source = path or self.asm_data_file
        if not source or not source.exists():
            return self.load_asm_data()
        try:
            text = source.read_text()
            data = json.loads(text.removeprefix("window.ASM_DATA = ").rstrip(";\n"))
            self.save_asm_data(data)
            return data
        except Exception:
            return self.load_asm_data()

    def get_asm_data_timestamp(self) -> float:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT updated_at FROM asm_data_state WHERE id = 1"
            ).fetchone()
        if not row:
            return 0.0
        try:
            return datetime.fromisoformat(row["updated_at"]).timestamp()
        except Exception:
            return 0.0

    def save_snapshot(self, company_id: str, payload: dict, *, slot: str = "current") -> None:
        ts = payload.get("ts") or self._now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO snapshots (company_id, slot, ts, payload_json)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(company_id, slot) DO UPDATE SET
                    ts=excluded.ts,
                    payload_json=excluded.payload_json
                """,
                (company_id, slot, ts, self._json_dumps(payload)),
            )
            conn.commit()
        self._sync_snapshots_dir()

    def load_snapshot(self, company_id: str, *, slot: str = "current") -> dict | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT payload_json FROM snapshots WHERE company_id = ? AND slot = ?",
                (company_id, slot),
            ).fetchone()
        if not row:
            return None
        return self._json_loads(row["payload_json"], None)

    # ── Subdomain history tracking ─────────────────────────────────────────────

    def insert_subdomain_history(
        self,
        company_id: str,
        subdomain: str,
        event: str,
        first_seen: str,
        last_seen: str,
        is_alive: int = 0,
        source: str = "",
    ) -> None:
        """Insert a new subdomain history entry."""
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO subdomain_history
                (company_id, subdomain, event, first_seen, last_seen, is_alive, source, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (company_id, subdomain, event, first_seen, last_seen, is_alive, source, self._now()),
            )
            conn.commit()

    def update_subdomain_history(
        self,
        company_id: str,
        subdomain: str,
        event: str,
        last_seen: str,
    ) -> None:
        """Update existing subdomain history entry (event: seen/removed)."""
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                UPDATE subdomain_history
                SET event = ?, last_seen = ?, updated_at = ?
                WHERE company_id = ? AND subdomain = ?
                """,
                (event, last_seen, self._now(), company_id, subdomain),
            )
            conn.commit()

    def get_subdomain_history(self, company_id: str, limit: int = 1000) -> list[dict]:
        """Get subdomain history for a company."""
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT subdomain, event, first_seen, last_seen, is_alive, source, created_at
                FROM subdomain_history
                WHERE company_id = ?
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (company_id, limit),
            ).fetchall()
        return [
            {
                "subdomain": row["subdomain"],
                "event": row["event"],
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
                "is_alive": bool(row["is_alive"]),
                "source": row["source"],
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def add_scan_stat(self, company_id: str, stats: dict) -> None:
        now = self._now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO scan_stats_history
                (company_id, scanned_at, subdomains, live_hosts,
                 findings_critical, findings_high, findings_medium, findings_low,
                 open_ports, waf_protected)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    company_id,
                    stats.get("scanned_at", now),
                    int(stats.get("subdomains", 0)),
                    int(stats.get("live_hosts", 0)),
                    int(stats.get("findings_critical", 0)),
                    int(stats.get("findings_high", 0)),
                    int(stats.get("findings_medium", 0)),
                    int(stats.get("findings_low", 0)),
                    int(stats.get("open_ports", 0)),
                    int(stats.get("waf_protected", 0)),
                ),
            )
            conn.commit()

    def get_scan_stats(self, company_id: str, limit: int = 30) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT scanned_at, subdomains, live_hosts,
                       findings_critical, findings_high, findings_medium, findings_low,
                       open_ports, waf_protected
                FROM scan_stats_history
                WHERE company_id = ?
                ORDER BY scanned_at DESC
                LIMIT ?
                """,
                (company_id, limit),
            ).fetchall()
        return [dict(row) for row in reversed(rows)]

    def get_alert_rules(self, company_id: str) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, company_id, name, rule_type, enabled, channels_json
                FROM alert_rules
                WHERE (company_id = ? OR company_id = '*') AND enabled = 1
                """,
                (company_id,),
            ).fetchall()
        return [
            {
                "id": row["id"],
                "company_id": row["company_id"],
                "name": row["name"],
                "rule_type": row["rule_type"],
                "enabled": bool(row["enabled"]),
                "channels": self._json_loads(row["channels_json"], []),
            }
            for row in rows
        ]

    def get_all_alert_rules(self, company_id: str) -> list[dict]:
        """All rules for a company (including disabled), for management UI."""
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, company_id, name, rule_type, enabled, channels_json, created_at
                FROM alert_rules
                WHERE company_id = ? OR company_id = '*'
                ORDER BY created_at DESC
                """,
                (company_id,),
            ).fetchall()
        return [
            {
                "id": row["id"],
                "company_id": row["company_id"],
                "name": row["name"],
                "rule_type": row["rule_type"],
                "enabled": bool(row["enabled"]),
                "channels": self._json_loads(row["channels_json"], []),
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def create_alert_rule(self, company_id: str, name: str, rule_type: str,
                          channels: list[str], enabled: bool = True) -> str:
        rule_id = uuid.uuid4().hex[:12]
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO alert_rules (id, company_id, name, rule_type, enabled, channels_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (rule_id, company_id, name, rule_type, 1 if enabled else 0,
                 self._json_dumps(channels), self._now()),
            )
            conn.commit()
        return rule_id

    def update_alert_rule(self, company_id: str, rule_id: str, **fields) -> bool:
        """Update one or more of: name, rule_type, enabled, channels."""
        columns = {"name": "name", "rule_type": "rule_type", "enabled": "enabled", "channels": "channels_json"}
        sets, params = [], []
        for key, column in columns.items():
            if key not in fields:
                continue
            value = fields[key]
            if key == "enabled":
                value = 1 if value else 0
            elif key == "channels":
                value = self._json_dumps(value)
            sets.append(f"{column} = ?")
            params.append(value)
        if not sets:
            return False
        params.extend([company_id, rule_id])
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                f"UPDATE alert_rules SET {', '.join(sets)} WHERE company_id = ? AND id = ?",
                params,
            )
            conn.commit()
        return cur.rowcount > 0

    def delete_alert_rule(self, company_id: str, rule_id: str) -> bool:
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM alert_rules WHERE company_id = ? AND id = ?",
                (company_id, rule_id),
            )
            conn.commit()
        return cur.rowcount > 0

    def create_alert(self, company_id: str, rule_type: str, title: str,
                     description: str, severity: str, data: dict) -> str:
        alert_id = uuid.uuid4().hex[:12]
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO alerts
                (id, company_id, rule_type, title, description, severity, data_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (alert_id, company_id, rule_type, title, description,
                 severity, self._json_dumps(data), self._now()),
            )
            conn.execute(
                """
                DELETE FROM alerts WHERE company_id = ? AND id NOT IN (
                    SELECT id FROM alerts WHERE company_id = ?
                    ORDER BY created_at DESC LIMIT 500
                )
                """,
                (company_id, company_id),
            )
            conn.commit()
        return alert_id

    # ─── Finding triage ─────────────────────────────────────────────────────────

    def get_finding_triage(self, company_id: str) -> dict[str, dict]:
        """Return {finding_key: {status, note, updated_by, updated_at}} for a company."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT finding_key, status, note, updated_by, updated_at FROM finding_triage WHERE company_id = ?",
                (company_id,),
            ).fetchall()
        return {
            row["finding_key"]: {
                "status": row["status"],
                "note": row["note"],
                "updated_by": row["updated_by"],
                "updated_at": row["updated_at"],
            }
            for row in rows
        }

    def set_finding_triage(self, company_id: str, finding_key: str, status: str,
                           note: str = "", updated_by: str = "") -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO finding_triage (company_id, finding_key, status, note, updated_by, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(company_id, finding_key) DO UPDATE SET
                    status = excluded.status,
                    note = excluded.note,
                    updated_by = excluded.updated_by,
                    updated_at = excluded.updated_at
                """,
                (company_id, finding_key, status, note, updated_by, self._now()),
            )
            conn.commit()

    def sync_legacy_files(self) -> None:
        self._sync_settings_file()
        self._sync_admins_file()
        self._sync_companies_file()
        self._sync_schedules_file()
        self._sync_webhooks_file()
        self._sync_whitelist_file()
        self._sync_audit_log_file()
        self._sync_asm_data_file()
        self._sync_snapshots_dir()

    def _sync_settings_file(self) -> None:
        if self.settings_file:
            payload = json.dumps(self.get_settings(), indent=2, ensure_ascii=False)
            self.settings_file.write_text(payload)
            # Redundant backup copy — survives accidental deletion/overwrite of
            # the primary settings file (e.g. manual cleanup, half-finished gitpull).
            backup = self.settings_file.with_name(self.settings_file.stem + ".backup.json")
            try:
                backup.write_text(payload)
            except Exception:
                pass

    def _sync_admins_file(self) -> None:
        if self.admins_file:
            self.admins_file.write_text(
                json.dumps({"admins": self.load_admins()}, indent=2, ensure_ascii=False)
            )

    def _sync_companies_file(self) -> None:
        if self.companies_file:
            self.companies_file.write_text(
                json.dumps({"companies": self.load_companies()}, indent=2, ensure_ascii=False)
            )

    def _sync_schedules_file(self) -> None:
        if self.schedules_file:
            self.schedules_file.write_text(
                json.dumps(self.load_schedules(), indent=2, ensure_ascii=False)
            )

    def _sync_webhooks_file(self) -> None:
        if self.webhooks_file:
            self.webhooks_file.write_text(
                json.dumps(self.load_webhooks(), indent=2, ensure_ascii=False)
            )

    def _sync_whitelist_file(self) -> None:
        if self.whitelist_file:
            self.whitelist_file.write_text(
                json.dumps(self.load_whitelist(), indent=2, ensure_ascii=False)
            )

    def _sync_audit_log_file(self) -> None:
        if not self.audit_log_file:
            return
        entries = self.list_audit_log(limit=5000)
        lines = [json.dumps(entry, ensure_ascii=False) for entry in reversed(entries)]
        self.audit_log_file.write_text(("\n".join(lines) + "\n") if lines else "")

    def _sync_asm_data_file(self) -> None:
        if not self.asm_data_file:
            return
        data = self.load_asm_data()
        js_out = "window.ASM_DATA = " + json.dumps(data, ensure_ascii=False, indent=2) + ";\n"
        self.asm_data_file.write_text(js_out)

    def _sync_snapshots_dir(self) -> None:
        if not self.snapshots_dir:
            return
        self.snapshots_dir.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT company_id, slot, payload_json FROM snapshots"
            ).fetchall()
        keep: set[Path] = set()
        for row in rows:
            suffix = "_prev" if row["slot"] == "previous" else ""
            path = self.snapshots_dir / f"{row['company_id']}{suffix}.json"
            keep.add(path)
            payload = self._json_loads(row["payload_json"], {})
            path.write_text(json.dumps(payload, indent=2, ensure_ascii=False))
        for path in self.snapshots_dir.glob("*.json"):
            if path not in keep:
                path.unlink(missing_ok=True)
