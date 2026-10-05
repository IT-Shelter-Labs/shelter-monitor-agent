"""systemd unit status via `systemctl show` (fixed argv, never a shell)."""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass


# SYSTEMD_IGNORE_CHROOT: inside a container systemctl may consider itself "in a chroot"
# and silently ignore commands; the host's systemd is reached via the mounted /run/systemd.
SYSTEMCTL_ENV = {"LANG": "C", "SYSTEMD_PAGER": "", "SYSTEMD_COLORS": "0", "SYSTEMD_IGNORE_CHROOT": "1",
                 "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}


@dataclass
class UnitStatus:
    name: str
    load_state: str     # loaded, not-found, masked...
    active_state: str   # active, inactive, failed, activating, deactivating, reloading
    sub_state: str      # running, exited, dead...
    description: str = ""
    since: str = ""

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


class SystemdClient:
    def __init__(self, systemctl: str | None = None, timeout: float = 15):
        self.systemctl = systemctl or shutil.which("systemctl") or "/usr/bin/systemctl"
        self.timeout = timeout

    def available(self) -> bool:
        return os.path.exists(self.systemctl) and os.path.isdir("/run/systemd/system")

    def _run(self, args: list[str]) -> str:
        proc = subprocess.run(
            [self.systemctl, *args], capture_output=True, text=True, timeout=self.timeout, check=False,
            env=SYSTEMCTL_ENV,
        )
        return proc.stdout

    def status(self, units: list[str]) -> list[UnitStatus]:
        if not units:
            return []
        out = self._run(
            ["show", "--no-pager", "-p", "Id,LoadState,ActiveState,SubState,Description,StateChangeTimestamp", "--", *units]
        )
        parsed = parse_show_output(out)
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
