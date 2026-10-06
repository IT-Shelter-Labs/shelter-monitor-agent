"""Log sources shared by the SSH and firewall watchers: journald (`journalctl -f -o json`)
or a tailed syslog file. Read positions are persisted so nothing is lost on restart."""

from __future__ import annotations

import datetime as dt
import glob
import json
import logging
import os
import shutil
import subprocess
import threading
import time
from typing import Any, Callable, Generic, Iterator, TypeVar

log = logging.getLogger(__name__)

T = TypeVar("T")


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


def parse_journal_entry(raw: str, parse: Callable[[str, float | None], T | None]) -> tuple[T | None, str | None]:
    """Parse one `journalctl -o json` line. Returns (record, cursor)."""
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
    return parse(message, ts), entry.get("__CURSOR")


def journal_available() -> bool:
    return shutil.which("journalctl") is not None and os.path.isdir("/run/systemd/system")


def journal_readable() -> bool:
    if os.geteuid() == 0:
        return True
    for pattern in ("/var/log/journal/*/system.journal", "/run/log/journal/*/system.journal"):
        for path in glob.glob(pattern):
            if os.access(path, os.R_OK):
                return True
    return False


class JournalSource(Generic[T]):
    """Follow journald entries matching `matches`; `parse(message, ts)` turns a message into a record."""

    name = "journal"

    def __init__(self, state: Any, stop: threading.Event, matches: list[str],
                 parse: Callable[[str, float | None], T | None], key: str, label: str = ""):
        self._state = state  # Storage (kv) for the journal cursor
        self._stop = stop
        self._matches = matches
        self._parse = parse
        self._key = key
        self._label = label or key
        self._proc: subprocess.Popen[str] | None = None
        self.error = ""

    def lines(self) -> Iterator[T]:
        journalctl = shutil.which("journalctl") or "/usr/bin/journalctl"
        while not self._stop.is_set():
            cursor = self._state.kv_get(f"{self._key}.journal_cursor")
            args = [journalctl, "--follow", "--output=json", "--no-pager", "--quiet"]
            # Resume after the last processed entry so logins during an agent restart are not lost.
            args += [f"--after-cursor={cursor}"] if cursor else ["--lines=0"]
            if not os.path.exists("/etc/machine-id"):  # container without the host's machine-id
                args.append("--merge")
            args += self._matches
            log.info("reading %s logs from journald", self._label)
            started = time.monotonic()
            try:
                self._proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                              env={"LANG": "C.UTF-8", "PATH": "/usr/bin:/bin"})
            except OSError as exc:
                log.error("cannot start journalctl: %s", exc)
                self._stop.wait(60)
                continue
            assert self._proc.stdout is not None
            last_cursor_save = 0.0
            for raw in self._proc.stdout:
                record, cur = parse_journal_entry(raw, self._parse)
                self.error = ""
                if cur and time.monotonic() - last_cursor_save > 5:
                    self._state.kv_set(f"{self._key}.journal_cursor", cur)
                    last_cursor_save = time.monotonic()
                if record is not None:
                    if cur:
                        self._state.kv_set(f"{self._key}.journal_cursor", cur)
                    yield record
                if self._stop.is_set():
                    break
            stderr = ""
            proc = self._proc
            if proc is not None and proc.stderr is not None and proc.poll() is not None:
                stderr = proc.stderr.read(2000).strip()
            self.close()
            if not self._stop.is_set():
                self.error = stderr.splitlines()[-1] if stderr else "journalctl завершился"
                if "cursor" in stderr.lower():  # stale cursor (journal rotated / other machine)
                    self._state.kv_delete(f"{self._key}.journal_cursor")
                delay = 10 if time.monotonic() - started > 60 else 60
                log.warning("journalctl (%s) exited: %s; restarting in %ss", self._label, self.error, delay)
                self._stop.wait(delay)

    def close(self) -> None:
        proc, self._proc = self._proc, None
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(5)
            except subprocess.TimeoutExpired:
                proc.kill()


class FileSource(Generic[T]):
    """Tail a syslog file, following logrotate (inode change / truncation)."""

    name = "file"

    def __init__(self, path: str, state: Any, stop: threading.Event, parse_line: Callable[[str], T | None],
                 key: str, poll: float = 1.0):
        self._path = path
        self._state = state
        self._stop = stop
        self._parse_line = parse_line
        self._key = key
        self._poll = poll
        self.error = ""

    def _open(self, resume: bool) -> tuple[Any, int] | None:
        try:
            fh = open(self._path, "rb")
        except OSError as exc:
            log.warning("cannot open %s: %s", self._path, exc)
            self.error = str(exc)
            return None
        self.error = ""
        st = os.fstat(fh.fileno())
        if resume:
            saved_inode, _, saved_pos = (self._state.kv_get(f"{self._key}.file_pos", "") or "").partition(":")
            if saved_inode == str(st.st_ino) and saved_pos.isdigit() and int(saved_pos) <= st.st_size:
                fh.seek(int(saved_pos))
            else:
                fh.seek(0, os.SEEK_END)  # first start: only new lines
        log.info("reading %s", self._path)
        return fh, st.st_ino

    def lines(self) -> Iterator[T]:
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
                record = self._parse_line(line)
                if record is not None:
                    self._state.kv_set(f"{self._key}.file_pos", f"{inode}:{fh.tell()}")
                    yield record
                continue
            self._state.kv_set(f"{self._key}.file_pos", f"{inode}:{fh.tell() - len(pending)}")
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
