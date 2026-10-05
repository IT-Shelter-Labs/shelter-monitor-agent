"""SSH login tracking and brute-force detection.

Log lines come either from journald (`journalctl -f -o json`, default on modern
Debian/Ubuntu) or from tailing /var/log/auth.log (systems with rsyslog).
"""

from __future__ import annotations

import collections
import datetime as dt
import glob
import ipaddress
import json
import logging
import os
import re
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Iterator

from shelter_monitor.agent.config import SSHSection
from shelter_monitor.agent.events import Event, EventBus
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


def parse_syslog_timestamp(line: str, now: dt.datetime | None = None) -> float | None:
    """Parse either an RFC3339 prefix ("2026-10-04T20:04:05.123+03:00 host ...")
    or the classic "Oct  4 20:04:05 host ..." prefix."""
    head = line.split(" ", 1)[0]
    if len(head) >= 19 and head[4] == "-" and "T" in head:
        try:
            return dt.datetime.fromisoformat(head.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return None
    try:
        parsed = dt.datetime.strptime(line[:15], "%b %d %H:%M:%S")
    except ValueError:
        return None
    now = now or dt.datetime.now()
    candidate = parsed.replace(year=now.year)
    if candidate > now + dt.timedelta(days=1):  # December lines read in January
        candidate = candidate.replace(year=now.year - 1)
    return candidate.timestamp()


def parse_syslog_line(line: str) -> SSHAuth | None:
    m = _SYSLOG_TAG.search(line)
    if not m:
        return None
    return parse_message(m["msg"], parse_syslog_timestamp(line))


def parse_journal_entry(raw: str) -> tuple[SSHAuth | None, str | None]:
    """Parse one `journalctl -o json` line. Returns (auth, cursor)."""
    try:
        entry = json.loads(raw)
    except ValueError:
        return None, None
    message = entry.get("MESSAGE")
    if isinstance(message, list):  # non-UTF-8 payloads are encoded as byte arrays
        message = bytes(message).decode("utf-8", errors="replace")
    if not isinstance(message, str):
        return None, entry.get("__CURSOR")
    ts = None
    if entry.get("__REALTIME_TIMESTAMP"):
        ts = int(entry["__REALTIME_TIMESTAMP"]) / 1e6
    return parse_message(message, ts), entry.get("__CURSOR")


# --- log sources -------------------------------------------------------------------


def journal_readable() -> bool:
    if os.geteuid() == 0:
        return True
    for pattern in ("/var/log/journal/*/system.journal", "/run/log/journal/*/system.journal"):
        for path in glob.glob(pattern):
            if os.access(path, os.R_OK):
                return True
    return False


class JournalSource:
    name = "journal"

    def __init__(self, state: Any, stop: threading.Event):
        self._state = state  # Storage (kv) for the journal cursor
        self._stop = stop
        self._proc: subprocess.Popen[str] | None = None

    def lines(self) -> Iterator[SSHAuth]:
        journalctl = shutil.which("journalctl") or "/usr/bin/journalctl"
        while not self._stop.is_set():
            cursor = self._state.kv_get("ssh.journal_cursor")
            args = [journalctl, "--follow", "--output=json", "--no-pager", "--quiet"]
            # Resume after the last processed entry so logins during an agent restart are not lost.
            args += [f"--after-cursor={cursor}"] if cursor else ["--lines=0"]
            if not os.path.exists("/etc/machine-id"):  # container without the host's machine-id
                args.append("--merge")
            args += [f"SYSLOG_IDENTIFIER={ident}" for ident in SSHD_IDENTIFIERS]
            log.info("reading sshd logs from journald")
            try:
                self._proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                                              env={"LANG": "C.UTF-8", "PATH": "/usr/bin:/bin"})
            except OSError as exc:
                log.error("cannot start journalctl: %s", exc)
                self._stop.wait(60)
                continue
            assert self._proc.stdout is not None
            last_cursor_save = 0.0
            for raw in self._proc.stdout:
                auth, cur = parse_journal_entry(raw)
                if cur and time.monotonic() - last_cursor_save > 5:
                    self._state.kv_set("ssh.journal_cursor", cur)
                    last_cursor_save = time.monotonic()
                if auth:
                    if cur:
                        self._state.kv_set("ssh.journal_cursor", cur)
                    yield auth
                if self._stop.is_set():
                    break
            self.close()
            if not self._stop.is_set():
                log.warning("journalctl exited, restarting in 10s")
                self._stop.wait(10)

    def close(self) -> None:
        proc, self._proc = self._proc, None
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(5)
            except subprocess.TimeoutExpired:
                proc.kill()


class FileSource:
    """Tail a syslog file, following logrotate (inode change / truncation)."""

    name = "file"

    def __init__(self, path: str, state: Any, stop: threading.Event, poll: float = 1.0):
        self._path = path
        self._state = state
        self._stop = stop
        self._poll = poll

    def _open(self, resume: bool) -> tuple[Any, int] | None:
        try:
            fh = open(self._path, "rb")
        except OSError as exc:
            log.warning("cannot open %s: %s", self._path, exc)
            return None
        st = os.fstat(fh.fileno())
        if resume:
            saved_inode, _, saved_pos = (self._state.kv_get("ssh.file_pos", "") or "").partition(":")
            if saved_inode == str(st.st_ino) and saved_pos.isdigit() and int(saved_pos) <= st.st_size:
                fh.seek(int(saved_pos))
            else:
                fh.seek(0, os.SEEK_END)  # first start: only new lines
        log.info("reading sshd logs from %s", self._path)
        return fh, st.st_ino

    def lines(self) -> Iterator[SSHAuth]:
        opened = None
        first = True
        pending = b""
        while not self._stop.is_set():
            if opened is None:
                opened = self._open(resume=first)
                if opened is None:
                    self._stop.wait(30)
                    continue
                first = False
                pending = b""
            fh, inode = opened
            chunk = fh.readline()
            if chunk:
                pending += chunk
                if not pending.endswith(b"\n"):
                    continue  # partial line: the rest arrives on a later read
                line, pending = pending.decode("utf-8", errors="replace").rstrip("\n"), b""
                auth = parse_syslog_line(line)
                if auth:
                    self._state.kv_set("ssh.file_pos", f"{inode}:{fh.tell()}")
                    yield auth
                continue
            self._state.kv_set("ssh.file_pos", f"{inode}:{fh.tell() - len(pending)}")
            self._stop.wait(self._poll)
            try:
                st = os.stat(self._path)
            except OSError:
                continue
            if st.st_ino != inode or st.st_size < fh.tell():
                log.info("%s rotated, reopening", self._path)
                fh.close()
                opened = self._open(resume=False)
                if opened is not None:
                    opened[0].seek(0)  # the new file: read from the beginning
        if opened:
            opened[0].close()

    def close(self) -> None:
        pass


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
            return JournalSource(self._storage, self._stop)
        return FileSource(self.cfg.log_file, self._storage, self._stop)

    def start(self, source_factory: Callable[[], Any] | None = None) -> None:
        self._source = (source_factory or self.select_source)()
        self.source_name = self._source.name
        self._thread = threading.Thread(target=self._run, name="ssh-watch", daemon=True)
        self._thread.start()

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
