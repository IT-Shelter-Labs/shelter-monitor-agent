"""System metrics read directly from /proc and /sys (no psutil needed)."""

from __future__ import annotations

import fnmatch
import glob
import os
import platform
import socket
import struct
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Any

# Filesystems worth reporting; pseudo filesystems (tmpfs, overlay, squashfs...) are skipped.
REAL_FS = {"ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs", "vfat", "exfat", "ntfs", "ntfs3", "fuseblk",
           "jfs", "reiserfs", "bcachefs", "nfs", "nfs4", "cifs"}
VIRTUAL_IFACE_PREFIXES = ("lo", "veth", "docker", "br-", "virbr", "vnet", "tap", "tun", "wg", "cni", "flannel",
                          "cali", "kube", "zt", "tailscale", "ifb", "dummy", "sit", "ip6tnl")


@dataclass
class DiskUsage:
    mount: str
    device: str
    fstype: str
    total: int
    used: int
    free: int

    @property
    def percent(self) -> float:
        # Same formula as df(1): blocks reserved for root count as unavailable.
        denom = self.used + self.free
        return 100.0 * self.used / denom if denom else 0.0


@dataclass
class MemoryUsage:
    total: int
    available: int
    swap_total: int
    swap_free: int

    @property
    def used(self) -> int:
        return self.total - self.available

    @property
    def percent(self) -> float:
        return 100.0 * self.used / self.total if self.total else 0.0

    @property
    def swap_used(self) -> int:
        return self.swap_total - self.swap_free

    @property
    def swap_percent(self) -> float:
        return 100.0 * self.swap_used / self.swap_total if self.swap_total else 0.0


@dataclass
class NetRate:
    iface: str
    rx_bytes: int
    tx_bytes: int
    rx_rate: float = 0.0
    tx_rate: float = 0.0


@dataclass
class Snapshot:
    ts: float
    hostname: str
    os_name: str
    kernel: str
    uptime: float
    cpu_count: int
    cpu_percent: float
    load: tuple[float, float, float]
    memory: MemoryUsage
    disks: list[DiskUsage]
    net: list[NetRate]
    temperature: float | None
    primary_ip: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def summary(self) -> dict[str, Any]:
        """Compact dict for heartbeats / hub."""
        return {
            "uptime": round(self.uptime),
            "cpu_percent": round(self.cpu_percent, 1),
            "load": [round(x, 2) for x in self.load],
            "cpu_count": self.cpu_count,
            "mem_percent": round(self.memory.percent, 1),
            "swap_percent": round(self.memory.swap_percent, 1),
            "disk_max_percent": round(max((d.percent for d in self.disks), default=0.0), 1),
            "temperature": self.temperature,
        }

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class SystemCollector:
    def __init__(self, proc: str = "/proc", sys: str = "/sys", etc: str = "/etc"):
        self.proc = proc
        self.sys = sys
        self.etc = etc

    def _read(self, rel: str) -> str:
        with open(os.path.join(self.proc, rel), encoding="utf-8", errors="replace") as fh:
            return fh.read()

    # -- CPU ----------------------------------------------------------------------------

    def cpu_times(self) -> tuple[int, int]:
        """Return (idle, total) jiffies from the aggregate cpu line of /proc/stat."""
        for line in self._read("stat").splitlines():
            if line.startswith("cpu "):
                values = [int(v) for v in line.split()[1:]]
                # user nice system idle iowait irq softirq steal guest guest_nice
                idle = values[3] + (values[4] if len(values) > 4 else 0)
                total = sum(values[:8])  # guest time is already included in user/nice
                return idle, total
        raise RuntimeError("no cpu line in /proc/stat")

    def cpu_count(self) -> int:
        return os.cpu_count() or 1

    def load(self) -> tuple[float, float, float]:
        parts = self._read("loadavg").split()
        return float(parts[0]), float(parts[1]), float(parts[2])

    # -- memory ---------------------------------------------------------------------

    def memory(self) -> MemoryUsage:
        info: dict[str, int] = {}
        for line in self._read("meminfo").splitlines():
            key, _, rest = line.partition(":")
            parts = rest.split()
            if parts:
                info[key] = int(parts[0]) * 1024
        total = info.get("MemTotal", 0)
        available = info.get("MemAvailable")
        if available is None:  # very old kernels
            available = info.get("MemFree", 0) + info.get("Buffers", 0) + info.get("Cached", 0)
        return MemoryUsage(total, available, info.get("SwapTotal", 0), info.get("SwapFree", 0))

    # -- uptime / identity ------------------------------------------------------------

    def uptime(self) -> float:
        return float(self._read("uptime").split()[0])

    def boot_id(self) -> str:
        try:
            return self._read("sys/kernel/random/boot_id").strip()
        except OSError:
            return ""

    def os_name(self) -> str:
        try:
            with open(os.path.join(self.etc, "os-release"), encoding="utf-8") as fh:
                for line in fh:
                    if line.startswith("PRETTY_NAME="):
                        return line.split("=", 1)[1].strip().strip('"')
        except OSError:
            pass
        return platform.system()

    # -- disks ----------------------------------------------------------------------

    def mounts(self) -> list[tuple[str, str, str]]:
        """Real filesystems from /proc/mounts as (device, mount, fstype), deduplicated by device."""
        seen: set[str] = set()
        result = []
        for line in self._read("mounts").splitlines():
            parts = line.split()
            if len(parts) < 3:
                continue
            device, mount, fstype = parts[0], parts[1].replace("\\040", " "), parts[2]
            if fstype not in REAL_FS:
                continue
            key = device if device.startswith("/dev/") else f"{device}:{mount}"
            if key in seen:  # bind mounts / btrfs subvolumes of the same device
                continue
            seen.add(key)
            result.append((device, mount, fstype))
        return result

    def disks(self, mounts: list[str] | None = None, ignore: list[str] | None = None) -> list[DiskUsage]:
        ignore = ignore or []
        if mounts:
            candidates = [("", m, "") for m in mounts]
        else:
            candidates = self.mounts()
        result = []
        for device, mount, fstype in candidates:
            if any(fnmatch.fnmatch(mount, pat) for pat in ignore):
                continue
            try:
                st = os.statvfs(mount)
            except OSError:
                continue
            total = st.f_blocks * st.f_frsize
            if total == 0:
                continue
            free = st.f_bavail * st.f_frsize  # space available to unprivileged users
            used = (st.f_blocks - st.f_bfree) * st.f_frsize
            result.append(DiskUsage(mount, device, fstype, total, used, free))
        return result

    # -- network --------------------------------------------------------------------

    def net_counters(self) -> dict[str, tuple[int, int]]:
        result = {}
        for line in self._read("net/dev").splitlines()[2:]:
            name, _, rest = line.partition(":")
            values = rest.split()
            if len(values) >= 9:
                result[name.strip()] = (int(values[0]), int(values[8]))
        return result

    @staticmethod
    def is_virtual_iface(name: str) -> bool:
        return name.startswith(VIRTUAL_IFACE_PREFIXES)

    def default_route(self) -> tuple[str, str] | None:
        """(interface, gateway_ip) of the IPv4 default route."""
        try:
            lines = self._read("net/route").splitlines()[1:]
        except OSError:
            return None
        for line in lines:
            parts = line.split()
            if len(parts) >= 3 and parts[1] == "00000000":
                gw = socket.inet_ntoa(struct.pack("<L", int(parts[2], 16)))
                return parts[0], gw
        return None

    def ipv4_routes(self) -> list[tuple[str, str]]:
        """Directly connected IPv4 networks as (iface, cidr)."""
        result = []
        try:
            lines = self._read("net/route").splitlines()[1:]
        except OSError:
            return result
        for line in lines:
            parts = line.split()
            if len(parts) < 8:
                continue
            iface, dest, gateway, flags, mask = parts[0], parts[1], parts[2], int(parts[3], 16), parts[7]
            if dest == "00000000" or gateway != "00000000" or not flags & 0x1:
                continue
            net = socket.inet_ntoa(struct.pack("<L", int(dest, 16)))
            prefix = bin(int(mask, 16)).count("1")
            result.append((iface, f"{net}/{prefix}"))
        return result

    @staticmethod
    def primary_ip() -> str:
        """Source address used for outbound traffic (no packets are actually sent)."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect(("192.0.2.1", 9))  # TEST-NET-1, never routed
            return sock.getsockname()[0]
        except OSError:
            return ""
        finally:
            sock.close()

    # -- temperature ----------------------------------------------------------------

    def temperature(self) -> float | None:
        temps = []
        for path in glob.glob(os.path.join(self.sys, "class/thermal/thermal_zone*/temp")):
            try:
                with open(path, encoding="utf-8") as fh:
                    value = int(fh.read().strip()) / 1000.0
            except (OSError, ValueError):
                continue
            if 0 < value < 150:
                temps.append(value)
        if not temps:
            for path in glob.glob(os.path.join(self.sys, "class/hwmon/hwmon*/temp*_input")):
                try:
                    with open(path, encoding="utf-8") as fh:
                        value = int(fh.read().strip()) / 1000.0
                except (OSError, ValueError):
                    continue
                if 0 < value < 150:
                    temps.append(value)
        return round(max(temps), 1) if temps else None


class CpuSampler:
    """CPU utilisation between consecutive calls. Each consumer owns its own sampler."""

    def __init__(self, collector: SystemCollector):
        self._collector = collector
        self._prev: tuple[int, int] | None = None
        self._lock = threading.Lock()

    def percent(self, min_window: float = 0.3) -> float:
        with self._lock:
            if self._prev is None:
                self._prev = self._collector.cpu_times()
                time.sleep(min_window)
            idle, total = self._collector.cpu_times()
            prev_idle, prev_total = self._prev
            self._prev = (idle, total)
        d_total = total - prev_total
        if d_total <= 0:
            return 0.0
        return max(0.0, min(100.0, 100.0 * (1 - (idle - prev_idle) / d_total)))


class NetSampler:
    def __init__(self, collector: SystemCollector, interfaces: list[str] | None = None):
        self._collector = collector
        self._interfaces = interfaces or []
        self._prev: tuple[float, dict[str, tuple[int, int]]] | None = None
        self._lock = threading.Lock()

    def rates(self) -> list[NetRate]:
        now = time.monotonic()
        counters = self._collector.net_counters()
        with self._lock:
            prev = self._prev
            self._prev = (now, counters)
        result = []
        for iface, (rx, tx) in counters.items():
            if self._interfaces:
                if iface not in self._interfaces:
                    continue
            elif SystemCollector.is_virtual_iface(iface):
                continue
            rate = NetRate(iface, rx, tx)
            if prev is not None and iface in prev[1]:
                dt = now - prev[0]
                if dt > 0:
                    rate.rx_rate = max(0.0, (rx - prev[1][iface][0]) / dt)
                    rate.tx_rate = max(0.0, (tx - prev[1][iface][1]) / dt)
            result.append(rate)
        return result


def take_snapshot(collector: SystemCollector, cpu: CpuSampler, net: NetSampler,
                  disk_mounts: list[str] | None = None, disk_ignore: list[str] | None = None) -> Snapshot:
    return Snapshot(
        ts=time.time(),
        hostname=socket.gethostname(),
        os_name=collector.os_name(),
        kernel=platform.release(),
        uptime=collector.uptime(),
        cpu_count=collector.cpu_count(),
        cpu_percent=cpu.percent(),
        load=collector.load(),
        memory=collector.memory(),
        disks=collector.disks(disk_mounts, disk_ignore),
        net=net.rates(),
        temperature=collector.temperature(),
        primary_ip=collector.primary_ip(),
    )
