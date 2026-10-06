"""systemd unit status via `systemctl show` (fixed argv, never a shell).

When the host's systemd cannot be reached (e.g. the agent runs in a container
without /run/systemd mounted) a *process-based* fallback reports whether the
service's main process is running. It is approximate and never raises alerts.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass

# SYSTEMD_IGNORE_CHROOT: inside a container systemctl may consider itself "in a chroot"
# and silently ignore commands; the host's systemd is reached via the mounted /run/systemd.
SYSTEMCTL_ENV = {"LANG": "C", "SYSTEMD_PAGER": "", "SYSTEMD_COLORS": "0", "SYSTEMD_IGNORE_CHROOT": "1",
                 "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}

# unit base name -> process names (as in /proc/<pid>/comm) of its main daemon
KNOWN_PROCESSES = {
    "ssh": ["sshd"], "sshd": ["sshd"], "openssh-server": ["sshd"],
    "cron": ["cron", "crond"], "crond": ["crond", "cron"], "cronie": ["crond"],
    "docker": ["dockerd"], "containerd": ["containerd"],
    "nginx": ["nginx"], "apache2": ["apache2"], "httpd": ["httpd"], "caddy": ["caddy"],
    "postgresql": ["postgres"], "mysql": ["mysqld"], "mariadb": ["mariadbd", "mysqld"],
    "redis-server": ["redis-server"], "redis": ["redis-server"], "mongod": ["mongod"],
    "fail2ban": ["fail2ban-server"], "crowdsec": ["crowdsec"], "rsyslog": ["rsyslogd"],
    "systemd-journald": ["systemd-journal"], "systemd-resolved": ["systemd-resolve"],
    "chrony": ["chronyd"], "chronyd": ["chronyd"], "systemd-timesyncd": ["systemd-timesyn"],
    "wg-quick@wg0": [], "tailscaled": ["tailscaled"], "smbd": ["smbd"], "nmbd": ["nmbd"],
    "php-fpm": ["php-fpm"], "ufw": [],
}


class SystemdError(Exception):
    pass


@dataclass
class UnitStatus:
    name: str
    load_state: str     # loaded, not-found, masked...  ("process" for the fallback)
    active_state: str   # active, inactive, failed, activating, deactivating, reloading
    sub_state: str      # running, exited, dead...
    description: str = ""
    since: str = ""
    approximate: bool = False  # derived from the process list, not from systemd

    @property
    def exists(self) -> bool:
        return self.load_state not in ("not-found", "")

    @property
    def ok(self) -> bool:
        return self.active_state in ("active", "reloading", "activating")


def parse_show_output(output: str) -> list[UnitStatus]:
    """Parse `systemctl show -p ... unit1 unit2`: key=value blocks separated by blank lines."""
    units = []
    for block in output.strip().split("\n\n"):
        props: dict[str, str] = {}
        for line in block.splitlines():
            key, sep, value = line.partition("=")
            if sep:
                props[key] = value
        if "Id" not in props:
            continue
        units.append(
            UnitStatus(
                name=props.get("Id", ""),
                load_state=props.get("LoadState", ""),
                active_state=props.get("ActiveState", ""),
                sub_state=props.get("SubState", ""),
                description=props.get("Description", ""),
                since=props.get("StateChangeTimestamp", ""),
            )
        )
    return units


def _short_error(stderr: str, returncode: int) -> str:
    lines = [ln.strip() for ln in stderr.strip().splitlines() if ln.strip()]
    return lines[-1][:300] if lines else f"systemctl exited with code {returncode}"


class SystemdClient:
    def __init__(self, systemctl: str | None = None, timeout: float = 15):
        self.systemctl = systemctl or shutil.which("systemctl") or "/usr/bin/systemctl"
        self.timeout = timeout

    def available(self) -> bool:
        return os.path.exists(self.systemctl) and os.path.isdir("/run/systemd/system")

    def unavailable_reason(self) -> str:
        if not os.path.exists(self.systemctl):
            return "systemctl не найден"
        if not os.path.isdir("/run/systemd/system"):
            return "нет /run/systemd/system (в Docker смонтируйте /run/systemd хоста)"
        return ""

    def _run(self, args: list[str]) -> str:
        try:
            proc = subprocess.run(
                [self.systemctl, *args], capture_output=True, text=True, timeout=self.timeout, check=False,
                env=SYSTEMCTL_ENV,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SystemdError(str(exc)) from None
        if proc.returncode != 0 and not proc.stdout.strip():
            raise SystemdError(_short_error(proc.stderr, proc.returncode))
        return proc.stdout

    def status(self, units: list[str]) -> list[UnitStatus]:
        """Raises SystemdError if systemd could not be queried (never reports that as 'not installed')."""
        if not units:
            return []
        out = self._run(
            ["show", "--no-pager", "-p", "Id,LoadState,ActiveState,SubState,Description,StateChangeTimestamp", "--", *units]
        )
        parsed = parse_show_output(out)
        if not parsed:
            raise SystemdError("systemctl show вернул пустой ответ")
        # Blocks come back in argument order. Aliases resolve to the canonical Id
        # (sshd.service -> ssh.service), so match by position and keep the requested name.
        if len(parsed) == len(units):
            for requested, unit in zip(units, parsed):
                unit.name = requested
            return parsed
        by_name = {u.name: u for u in parsed}
        return [by_name.get(u) or UnitStatus(u, "not-found", "inactive", "dead") for u in units]

    def failed_units(self) -> list[str]:
        out = self._run(["list-units", "--state=failed", "--plain", "--no-legend", "--no-pager"])
        result = []
        for line in out.splitlines():
            parts = line.split()
            if parts:
                name = parts[0].lstrip("●").strip() or (parts[1] if len(parts) > 1 else "")
                if name:
                    result.append(name)
        return result


# --- process-based fallback ------------------------------------------------------------


def host_proc_root(host_root: str = "") -> str | None:
    """A /proc that shows the HOST's processes (PID 1 is the host's init), or None."""
    candidates = ([os.path.join(host_root, "proc")] if host_root else []) + ["/proc"]
    for root in candidates:
        try:
            with open(os.path.join(root, "1", "comm"), encoding="utf-8") as fh:
                if fh.read().strip() in ("systemd", "init"):
                    return root
        except OSError:
            continue
    return None


def process_names(proc_root: str) -> set[str]:
    names = set()
    try:
        entries = os.listdir(proc_root)
    except OSError:
        return names
    for pid in entries:
        if not pid.isdigit():
            continue
        try:
            with open(os.path.join(proc_root, pid, "comm"), encoding="utf-8", errors="replace") as fh:
                names.add(fh.read().strip())
        except OSError:
            continue
    return names


def candidate_processes(unit: str) -> list[str]:
    base = unit.rsplit(".", 1)[0] if unit.endswith(".service") else unit
    if base in KNOWN_PROCESSES:
        return KNOWN_PROCESSES[base]
    base = base.split("@", 1)[0]
    candidates = [base, base + "d"]
    if base.endswith("d"):
        candidates.append(base[:-1])
    return [c[:15] for c in candidates]  # comm is truncated to 15 characters


def status_from_processes(units: list[str], proc_root: str) -> list[UnitStatus]:
    running = process_names(proc_root)
    result = []
    for unit in units:
        candidates = candidate_processes(unit)
        if not candidates:  # oneshot units (ufw, wg-quick) have no daemon process
            result.append(UnitStatus(unit, "process", "unknown", "no-process", approximate=True))
            continue
        found = next((c for c in candidates if c in running), None)
        if found:
            result.append(UnitStatus(unit, "process", "active", "running", f"процесс {found}", approximate=True))
        else:
            result.append(UnitStatus(unit, "process", "inactive", "dead",
                                     f"процесс не найден ({', '.join(candidates)})", approximate=True))
    return result


class ServiceProbe:
    """systemd first, process list as a fallback. `status()` returns (units, source, error)."""

    def __init__(self, client: SystemdClient, host_root: str = ""):
        self.client = client
        self.host_root = host_root
        self.last_error = ""
        self.source = ""

    def status(self, units: list[str]) -> tuple[list[UnitStatus], str, str]:
        error = ""
        if self.client.available():
            try:
                result = self.client.status(units)
                self.last_error, self.source = "", "systemd"
                return result, "systemd", ""
            except SystemdError as exc:
                error = str(exc)
        else:
            error = self.client.unavailable_reason()
        self.last_error = error
        proc_root = host_proc_root(self.host_root)
        if proc_root and units:
            self.source = "processes"
            return status_from_processes(units, proc_root), "processes", error
        self.source = ""
        return [], "", error or "нет доступа ни к systemd, ни к процессам хоста"

    def failed_units(self) -> list[str]:
        if self.source != "systemd":
            return []
        try:
            return self.client.failed_units()
        except SystemdError:
            return []
