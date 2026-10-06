"""Detection of how the agent is deployed (bare host / container, network mode)."""

from __future__ import annotations

import os
import re

# Interfaces that exist only in the host's network namespace of a Docker host.
_HOST_ONLY_IFACE_PREFIXES = ("docker", "br-", "veth")


def in_container() -> bool:
    if os.path.exists("/.dockerenv") or os.path.exists("/run/.containerenv"):
        return True
    try:
        with open("/proc/1/cgroup", encoding="utf-8") as fh:
            data = fh.read()
        return "docker" in data or "containerd" in data or "kubepods" in data
    except OSError:
        return False


def interfaces(proc: str = "/proc") -> list[str]:
    try:
        with open(os.path.join(proc, "net", "dev"), encoding="utf-8") as fh:
            lines = fh.read().splitlines()[2:]
    except OSError:
        return []
    return [line.split(":", 1)[0].strip() for line in lines if ":" in line]


def uses_host_network(proc: str = "/proc") -> bool:
    """True when the agent sees the host's network namespace.

    In a container with its own network namespace only `lo` and `eth*` are visible,
    while the host namespace of a Docker host always has docker0 / br-* / veth*.
    """
    if not in_container():
        return True
    names = interfaces(proc)
    if any(n.startswith(_HOST_ONLY_IFACE_PREFIXES) for n in names):
        return True
    # A bridged container sees only lo and eth0, eth1... (one per attached network);
    # anything else (ens3, enp1s0, wlan0, wg0...) belongs to the host namespace.
    return any(n != "lo" and not re.fullmatch(r"eth\d+", n) for n in names)


_CONTAINER_ID_RE = re.compile(r"/(?:docker/containers|containers|docker)/([0-9a-f]{64})")


def container_id_from_mountinfo(text: str) -> str:
    """Docker bind-mounts /etc/hostname, /etc/hosts and /etc/resolv.conf from
    /var/lib/docker/containers/<id>/ - only those lines identify *our* container
    (with the host's / mounted at /host, other containers' paths appear too)."""
    for line in text.splitlines():
        fields = line.split()
        if len(fields) > 4 and fields[4] in ("/etc/hostname", "/etc/hosts", "/etc/resolv.conf"):
            m = _CONTAINER_ID_RE.search(fields[3])
            if m:
                return m.group(1)
    return ""


def own_container_id() -> str:
    """Full ID of the Docker container the agent runs in ("" on a bare host)."""
    if not in_container():
        return ""
    try:
        with open("/proc/self/mountinfo", encoding="utf-8") as fh:
            found = container_id_from_mountinfo(fh.read())
        if found:
            return found
    except OSError:
        pass
    try:
        with open("/proc/self/cgroup", encoding="utf-8") as fh:  # cgroup v1
            m = _CONTAINER_ID_RE.search(fh.read())
        return m.group(1) if m else ""
    except OSError:
        return ""
