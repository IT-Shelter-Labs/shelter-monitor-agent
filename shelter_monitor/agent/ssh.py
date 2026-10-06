"""SSH login tracking and brute-force detection.

Log lines come either from journald (`journalctl -f -o json`, default on modern
Debian/Ubuntu) or from tailing /var/log/auth.log (systems with rsyslog).
"""

from __future__ import annotations

import collections
import ipaddress
import logging
import os
import re
import shutil
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable

from shelter_monitor.agent.config import SSHSection
from shelter_monitor.agent.events import Event, EventBus
from shelter_monitor.agent.logsources import FileSource, JournalSource, journal_readable, parse_syslog_timestamp
from shelter_monitor.agent.logsources import parse_journal_entry as _parse_journal_entry
from shelter_monitor.util import esc, fmt_duration

log = logging.getLogger(__name__)

SSHD_IDENTIFIERS = ("sshd", "sshd-session")  # OpenSSH 9.8+ logs from sshd-session

_ACCEPTED = re.compile(r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
_FAILED = re.compile(r"Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>\S*) from (?P<ip>\S+) port (?P<port>\d+)")
_INVALID = re.compile(r"Invalid user (?P<user>\S*) from (?P<ip>\S+)(?: port (?P<port>\d+))?")
_CLOSED_PREAUTH = re.compile(
    r"Connection (?:closed|reset) by authenticating user (?P<user>\S+) (?P<ip>\S+) port (?P<port>\d+) \[preauth\]"
)
_MAX_ATTEMPTS = re.compile(
    r"maximum authentication attempts exceeded for (?:invalid user )?(?P<user>\S*) from (?P<ip>\S+) port (?P<port>\d+)"
)
_SYSLOG_TAG = re.compile(r"\s(?P<ident>sshd(?:-session)?)\[\d+\]:\s(?P<msg>.*)$")


@dataclass
class SSHAuth:
    ts: float
    success: bool
    user: str
    ip: str
    method: str = ""
    port: int | None = None
    kind: str = ""


def parse_message(message: str, ts: float | None = None) -> SSHAuth | None:
    """Parse a single sshd message (without the syslog prefix)."""
    ts = ts if ts is not None else time.time()
    m = _ACCEPTED.search(message)
    if m:
        return SSHAuth(ts, True, m["user"], m["ip"], m["method"], int(m["port"]), "accepted")
    m = _FAILED.search(message)
    if m:
        if m["invalid"]:
            return None  # already counted by the preceding "Invalid user" line
        return SSHAuth(ts, False, m["user"], m["ip"], m["method"], int(m["port"]), "failed")
    m = _INVALID.search(message)
    if m:
        return SSHAuth(ts, False, m["user"], m["ip"], "", int(m["port"]) if m["port"] else None, "invalid_user")
    m = _MAX_ATTEMPTS.search(message)
    if m:
        return SSHAuth(ts, False, m["user"], m["ip"], "", int(m["port"]), "max_attempts")
    m = _CLOSED_PREAUTH.search(message)
    if m:
        return SSHAuth(ts, False, m["user"], m["ip"], "", int(m["port"]), "preauth_closed")
    return None


def parse_syslog_line(line: str) -> SSHAuth | None:
    m = _SYSLOG_TAG.search(line)
    if not m:
        return None
    return parse_message(m["msg"], parse_syslog_timestamp(line))


def parse_journal_entry(raw: str) -> tuple[SSHAuth | None, str | None]:
    """Parse one `journalctl -o json` line. Returns (auth, cursor)."""
    return _parse_journal_entry(raw, parse_message)


# --- log sources -------------------------------------------------------------------


def journal_source(state: Any, stop: threading.Event) -> JournalSource:
    return JournalSource(state, stop, [f"SYSLOG_IDENTIFIER={i}" for i in SSHD_IDENTIFIERS], parse_message,
                         key="ssh", label="sshd")


def file_source(path: str, state: Any, stop: threading.Event, poll: float = 1.0) -> FileSource:
    return FileSource(path, state, stop, parse_syslog_line, key="ssh", poll=poll)


# --- detection ---------------------------------------------------------------------


class SSHWatcher:
    """Stores SSH auth records, notifies about logins and detects brute force."""

    MAX_TRACKED_IPS = 20000

    def __init__(self, cfg: SSHSection, storage: Any, bus: EventBus):
        self.cfg = cfg
        self._storage = storage
        self._bus = bus
        self._trusted = [ipaddress.ip_network(n, strict=False) for n in cfg.trusted_networks]
        self._failures: dict[str, collections.deque[tuple[float, str]]] = {}
        self._alerted_until: dict[str, float] = {}
        self._global: collections.deque[float] = collections.deque()
        self._global_alerted_until = 0.0
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._source: Any = None
        self.source_name = ""

    def is_trusted(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self._trusted)

    def handle(self, auth: SSHAuth) -> None:
        try:
            self._storage.add_ssh(auth.ts, auth.success, auth.user, auth.ip, auth.method, auth.port)
        except Exception:
            log.exception("failed to store ssh record")
        if auth.success:
            self._on_success(auth)
        else:
            self._on_failure(auth)

    def _recent_failures(self, ip: str, now: float) -> int:
        with self._lock:
            q = self._failures.get(ip)
            return sum(1 for ts, _ in q if ts >= now - self.cfg.bruteforce_window) if q else 0

    def _on_success(self, auth: SSHAuth) -> None:
        trusted = self.is_trusted(auth.ip)
        prior_failures = self._recent_failures(auth.ip, auth.ts)
        body = (f"👤 <b>{esc(auth.user)}</b> с <code>{esc(auth.ip)}</code>\n"
                f"Метод: {esc(auth.method)}" + (f", порт {auth.port}" if auth.port else ""))
        if prior_failures >= 3:
            self._bus.emit(Event(
                "security", "critical", "ssh_login_after_failures", "Успешный SSH-вход после серии неудачных попыток",
                body + f"\nНеудачных попыток с этого IP за {fmt_duration(self.cfg.bruteforce_window)}: <b>{prior_failures}</b>",
                data={"user": auth.user, "ip": auth.ip, "failures": prior_failures}, ts=auth.ts))
            return
        notify = self.cfg.notify_success and not trusted
        self._bus.emit(Event("ssh", "info", "ssh_login", f"SSH-вход: {auth.user}", body,
                             data={"user": auth.user, "ip": auth.ip, "method": auth.method, "notify": notify,
                                   "silent": False}, ts=auth.ts))

    def _on_failure(self, auth: SSHAuth) -> None:
        now = auth.ts
        window_start = now - self.cfg.bruteforce_window
        with self._lock:
            q = self._failures.setdefault(auth.ip, collections.deque())
            q.append((now, auth.user))
            while q and q[0][0] < window_start:
                q.popleft()
            count = len(q)
            users = sorted({u for _, u in q if u})
            self._global.append(now)
            while self._global and self._global[0] < window_start:
                self._global.popleft()
            global_count = len(self._global)
            if len(self._failures) > self.MAX_TRACKED_IPS:
                self._prune(window_start)
            fire_ip = count >= self.cfg.bruteforce_threshold and self._alerted_until.get(auth.ip, 0) < now
            if fire_ip:
                self._alerted_until[auth.ip] = now + self.cfg.bruteforce_cooldown
            global_threshold = self.cfg.bruteforce_threshold * 5
            fire_global = global_count >= global_threshold and self._global_alerted_until < now
            if fire_global:
                self._global_alerted_until = now + self.cfg.bruteforce_cooldown

        if fire_ip:
            users_txt = ", ".join(esc(u) for u in users[:10]) + (" …" if len(users) > 10 else "")
            self._bus.emit(Event(
                "security", "warning", "ssh_bruteforce", "Подбор пароля SSH",
                f"IP <code>{esc(auth.ip)}</code>: <b>{count}</b> неудачных попыток за "
                f"{fmt_duration(self.cfg.bruteforce_window)}\nПользователи: {users_txt or '—'}\n"
                f"Повторное уведомление по этому IP не раньше чем через {fmt_duration(self.cfg.bruteforce_cooldown)}.",
                data={"ip": auth.ip, "count": count, "users": users[:20]}, ts=now))
        if fire_global:
            with self._lock:
                ips = len({ip for ip, q in self._failures.items() if q and q[-1][0] >= window_start})
            self._bus.emit(Event(
                "security", "warning", "ssh_mass_attack", "Массовые неудачные попытки входа по SSH",
                f"<b>{global_count}</b> неудачных попыток с <b>{ips}</b> IP за {fmt_duration(self.cfg.bruteforce_window)}.\n"
                "Рекомендуется вход только по ключам и fail2ban/crowdsec.",
                data={"count": global_count, "ips": ips}, ts=now))

    def _prune(self, window_start: float) -> None:
        for ip in [ip for ip, q in self._failures.items() if not q or q[-1][0] < window_start]:
            self._failures.pop(ip, None)
        now = time.time()
        for ip in [ip for ip, until in self._alerted_until.items() if until < now]:
            self._alerted_until.pop(ip, None)

    # -- background reading -----------------------------------------------------------

    def select_source(self) -> Any:
        mode = self.cfg.source
        if mode == "auto":
            has_journal = shutil.which("journalctl") is not None and os.path.isdir("/run/systemd/system")
            if has_journal and journal_readable():
                mode = "journal"
            elif os.access(self.cfg.log_file, os.R_OK):
                mode = "file"
            elif has_journal:
                mode = "journal"
            else:
                mode = "file"
        if mode == "journal":
            return journal_source(self._storage, self._stop)
        return file_source(self.cfg.log_file, self._storage, self._stop)

    def start(self, source_factory: Callable[[], Any] | None = None) -> None:
        self._source = (source_factory or self.select_source)()
        self.source_name = self._source.name
        self._thread = threading.Thread(target=self._run, name="ssh-watch", daemon=True)
        self._thread.start()

    @property
    def source_error(self) -> str:
        return getattr(self._source, "error", "") if self._source else ""

    def _run(self) -> None:
        try:
            for auth in self._source.lines():
                self.handle(auth)
        except Exception:
            log.exception("ssh watcher crashed")

    def stop(self) -> None:
        self._stop.set()
        if self._source:
            self._source.close()
