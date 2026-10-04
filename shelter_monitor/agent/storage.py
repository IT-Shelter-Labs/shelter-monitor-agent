"""SQLite storage for events, SSH authentication records, LAN devices and small state."""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from dataclasses import dataclass
from typing import Any, Iterator

SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    host TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    kind TEXT NOT NULL,
    title TEXT NOT NULL,
    body TEXT NOT NULL DEFAULT '',
    data TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);

CREATE TABLE IF NOT EXISTS ssh_auth (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    success INTEGER NOT NULL,
    user TEXT NOT NULL,
    ip TEXT NOT NULL,
    method TEXT NOT NULL DEFAULT '',
    port INTEGER
);
CREATE INDEX IF NOT EXISTS idx_ssh_ts ON ssh_auth(ts);
CREATE INDEX IF NOT EXISTS idx_ssh_success_ts ON ssh_auth(success, ts);

CREATE TABLE IF NOT EXISTS devices (
    mac TEXT PRIMARY KEY,
    ip TEXT NOT NULL,
    hostname TEXT NOT NULL DEFAULT '',
    iface TEXT NOT NULL DEFAULT '',
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    trusted INTEGER NOT NULL DEFAULT 0,
    name TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS kv (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


@dataclass
class EventRow:
    id: int
    ts: float
    host: str
    category: str
    severity: str
    kind: str
    title: str
    body: str
    data: dict[str, Any]


@dataclass
class SSHRow:
    ts: float
    success: bool
    user: str
    ip: str
    method: str
    port: int | None


@dataclass
class DeviceRow:
    mac: str
    ip: str
    hostname: str
    iface: str
    first_seen: float
    last_seen: float
    trusted: bool
    name: str


class Storage:
    def __init__(self, path: str):
        if path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None, timeout=10)
        self._db.row_factory = sqlite3.Row
        with self._lock:
            if path != ":memory:":
                self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute("PRAGMA synchronous=NORMAL")
            self._db.executescript(SCHEMA)
            self._db.execute("INSERT OR IGNORE INTO kv(key, value) VALUES ('schema_version', ?)", (str(SCHEMA_VERSION),))
        if path != ":memory:":
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def _exec(self, sql: str, params: tuple[Any, ...] = ()) -> sqlite3.Cursor:
        with self._lock:
            return self._db.execute(sql, params)

    def _query(self, sql: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._db.execute(sql, params).fetchall()

    # -- key/value ------------------------------------------------------------------

    def kv_get(self, key: str, default: str | None = None) -> str | None:
        rows = self._query("SELECT value FROM kv WHERE key = ?", (key,))
        return rows[0]["value"] if rows else default

    def kv_set(self, key: str, value: str) -> None:
        self._exec("INSERT INTO kv(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, value))

    def kv_delete(self, key: str) -> None:
        self._exec("DELETE FROM kv WHERE key = ?", (key,))

    # -- events ---------------------------------------------------------------------

    def add_event(
        self, ts: float, host: str, category: str, severity: str, kind: str, title: str, body: str, data: dict[str, Any]
    ) -> int:
        cur = self._exec(
            "INSERT INTO events(ts, host, category, severity, kind, title, body, data) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (ts, host, category, severity, kind, title, body, json.dumps(data, default=str)),
        )
        return int(cur.lastrowid or 0)

    def recent_events(self, limit: int = 20, min_severity: str | None = None) -> list[EventRow]:
        sql = "SELECT * FROM events"
        params: tuple[Any, ...] = ()
        if min_severity == "warning":
            sql += " WHERE severity IN ('warning', 'critical')"
        elif min_severity == "critical":
            sql += " WHERE severity = 'critical'"
        sql += " ORDER BY id DESC LIMIT ?"
        params = (limit,)
        return [
            EventRow(
                r["id"], r["ts"], r["host"], r["category"], r["severity"], r["kind"], r["title"], r["body"],
                json.loads(r["data"] or "{}"),
            )
            for r in self._query(sql, params)
        ]

    # -- ssh ------------------------------------------------------------------------

    def add_ssh(self, ts: float, success: bool, user: str, ip: str, method: str = "", port: int | None = None) -> None:
        self._exec(
            "INSERT INTO ssh_auth(ts, success, user, ip, method, port) VALUES (?, ?, ?, ?, ?, ?)",
            (ts, int(success), user, ip, method, port),
        )

    def recent_ssh_logins(self, limit: int = 10) -> list[SSHRow]:
        rows = self._query("SELECT * FROM ssh_auth WHERE success = 1 ORDER BY ts DESC LIMIT ?", (limit,))
        return [SSHRow(r["ts"], True, r["user"], r["ip"], r["method"], r["port"]) for r in rows]

    def ssh_failure_stats(self, since: float, limit: int = 10) -> list[dict[str, Any]]:
        rows = self._query(
            """SELECT ip, COUNT(*) AS cnt, MAX(ts) AS last_ts, COUNT(DISTINCT user) AS users
               FROM ssh_auth WHERE success = 0 AND ts >= ? GROUP BY ip ORDER BY cnt DESC LIMIT ?""",
            (since, limit),
        )
        return [dict(r) for r in rows]

    def ssh_failure_total(self, since: float) -> int:
        rows = self._query("SELECT COUNT(*) AS cnt FROM ssh_auth WHERE success = 0 AND ts >= ?", (since,))
        return int(rows[0]["cnt"])

    # -- devices --------------------------------------------------------------------

    def get_device(self, mac: str) -> DeviceRow | None:
        rows = self._query("SELECT * FROM devices WHERE mac = ?", (mac,))
        return self._device(rows[0]) if rows else None

    def upsert_device(self, mac: str, ip: str, hostname: str, iface: str, ts: float, trusted: bool = False) -> bool:
        """Insert or refresh a device. Returns True if the device was not known before."""
        with self._lock:
            existing = self._db.execute("SELECT mac FROM devices WHERE mac = ?", (mac,)).fetchone()
            if existing:
                self._db.execute(
                    """UPDATE devices SET ip = ?, last_seen = ?, iface = ?,
                       hostname = CASE WHEN ? != '' THEN ? ELSE hostname END WHERE mac = ?""",
                    (ip, ts, iface, hostname, hostname, mac),
                )
                return False
            self._db.execute(
                "INSERT INTO devices(mac, ip, hostname, iface, first_seen, last_seen, trusted) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (mac, ip, hostname, iface, ts, ts, int(trusted)),
            )
            return True

    def list_devices(self) -> list[DeviceRow]:
        return [self._device(r) for r in self._query("SELECT * FROM devices ORDER BY last_seen DESC")]

    def device_count(self) -> int:
        return int(self._query("SELECT COUNT(*) AS cnt FROM devices")[0]["cnt"])

    def set_device_trusted(self, mac: str, trusted: bool) -> bool:
        cur = self._exec("UPDATE devices SET trusted = ? WHERE mac = ?", (int(trusted), mac))
        return cur.rowcount > 0

    @staticmethod
    def _device(r: sqlite3.Row) -> DeviceRow:
        return DeviceRow(
            r["mac"], r["ip"], r["hostname"], r["iface"], r["first_seen"], r["last_seen"], bool(r["trusted"]), r["name"]
        )

    # -- maintenance ----------------------------------------------------------------

    def cleanup(self, retention_days: int) -> None:
        cutoff = time.time() - retention_days * 86400
        self._exec("DELETE FROM events WHERE ts < ?", (cutoff,))
        self._exec("DELETE FROM ssh_auth WHERE ts < ?", (cutoff,))

    def iter_tables(self) -> Iterator[str]:  # used by tests / diagnostics
        for r in self._query("SELECT name FROM sqlite_master WHERE type = 'table'"):
            yield r["name"]
