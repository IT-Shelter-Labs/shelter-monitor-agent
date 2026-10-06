"""Who is knocking: firewall log analysis and inbound connection tracking.

* FirewallWatcher reads packets blocked by the firewall (UFW / iptables LOG rules)
  from the kernel log and detects port scans: one IP probing many different ports.
* ConnectionMonitor polls /proc/net/tcp{,6} and reports *established* inbound
  connections from the internet to sensitive ports (RDP, VNC, databases, Docker API...).
"""

from __future__ import annotations

import collections
import ipaddress
import logging
import os
import re
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable

from shelter_monitor.agent.config import ConnectionsSection, FirewallSection
from shelter_monitor.agent.events import Event, EventBus
from shelter_monitor.agent.logsources import FileSource, JournalSource, journal_available, journal_readable
from shelter_monitor.agent.logsources import parse_syslog_timestamp
from shelter_monitor.util import esc, fmt_duration

log = logging.getLogger(__name__)

PORT_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 80: "HTTP", 443: "HTTPS", 445: "SMB", 1433: "MSSQL",
    2375: "Docker API", 2376: "Docker API (TLS)", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-alt", 9200: "Elasticsearch", 11211: "Memcached",
    27017: "MongoDB", 5672: "RabbitMQ", 8086: "InfluxDB", 9090: "Prometheus", 10250: "Kubelet",
}


def port_label(port: int) -> str:
    name = PORT_NAMES.get(port)
    return f"{port} ({name})" if name else str(port)


# --- firewall log -------------------------------------------------------------------

_FW_RE = re.compile(r"IN=(?P<in>\S*) OUT=(?P<out>\S*)\s.*?\bSRC=(?P<src>[0-9a-fA-F.:]+) DST=(?P<dst>[0-9a-fA-F.:]+)"
                    r".*?\bPROTO=(?P<proto>\w+)(?:.*?\bDPT=(?P<dpt>\d+))?")
_PREFIX_RE = re.compile(r"\[(?P<bracket>[^\]]+)\]\s*IN=|(?P<plain>[A-Za-z][\w :-]{1,40}?)\s*IN=")
_KERNEL_TAG = re.compile(r"\skernel:\s")


@dataclass
class FirewallHit:
    ts: float
    src: str
    dport: int | None
    proto: str
    prefix: str


def parse_firewall_message(message: str, ts: float | None = None) -> FirewallHit | None:
    """Parse a kernel netfilter LOG line, return inbound *blocked* packets only."""
    if "SRC=" not in message or "IN=" not in message:
        return None
    m = _FW_RE.search(message)
    if not m or not m["in"] or m["out"]:  # outbound or forwarded traffic
        return None
    pm = _PREFIX_RE.search(message)
    prefix = ""
    if pm:
        prefix = (pm["bracket"] or pm["plain"] or "").strip()
        if re.fullmatch(r"\s*\d+\.\d+", prefix):  # "[12345.678]" kernel uptime stamp, not a prefix
            prefix = ""
    upper = prefix.upper()
    if any(word in upper for word in ("ALLOW", "AUDIT", "ACCEPT")):
        return None
    dport = int(m["dpt"]) if m["dpt"] else None
    return FirewallHit(ts if ts is not None else time.time(), m["src"], dport, m["proto"].upper(), prefix)


def parse_firewall_line(line: str) -> FirewallHit | None:
    if not _KERNEL_TAG.search(line):
        return None
    return parse_firewall_message(line, parse_syslog_timestamp(line))


class FirewallWatcher:
    """Consumes firewall hits, keeps 24h statistics and raises port-scan alerts."""

    MAX_HITS = 20000

    def __init__(self, cfg: FirewallSection, storage: Any, bus: EventBus):
        self.cfg = cfg
        self._storage = storage
        self._bus = bus
        self._hits: collections.deque[FirewallHit] = collections.deque(maxlen=self.MAX_HITS)
        self._recent: dict[str, collections.deque[tuple[float, int]]] = {}
        self._alerted_until: dict[str, float] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._source: Any = None
        self.source_name = ""
        self.last_hit = 0.0

    def handle(self, hit: FirewallHit) -> None:
        window_start = hit.ts - self.cfg.scan_window
        with self._lock:
            self._hits.append(hit)
            self.last_hit = max(self.last_hit, hit.ts)
            q = self._recent.setdefault(hit.src, collections.deque())
            q.append((hit.ts, hit.dport or 0))
            while q and q[0][0] < window_start:
                q.popleft()
            ports = {p for _, p in q if p}
            fire = len(ports) >= self.cfg.scan_ports and self._alerted_until.get(hit.src, 0) < hit.ts
            if fire:
                self._alerted_until[hit.src] = hit.ts + self.cfg.cooldown
            if len(self._recent) > 5000:
                for ip in [ip for ip, dq in self._recent.items() if not dq or dq[-1][0] < window_start]:
                    del self._recent[ip]
        if fire:
            sample = ", ".join(port_label(p) for p in sorted(ports)[:12]) + (" …" if len(ports) > 12 else "")
            self._bus.emit(Event(
                "security", "warning", "port_scan", "Сканирование портов",
                f"IP <code>{esc(hit.src)}</code> перебрал <b>{len(ports)}</b> портов за "
                f"{fmt_duration(self.cfg.scan_window)} (заблокировано файрволом)\nПорты: {esc(sample)}\n"
                f"Повторное уведомление по этому IP не раньше чем через {fmt_duration(self.cfg.cooldown)}.",
                data={"ip": hit.src, "ports": sorted(ports)[:50]}, ts=hit.ts))

    def stats(self, since: float) -> dict[str, Any]:
        with self._lock:
            hits = [h for h in self._hits if h.ts >= since]
        by_ip: dict[str, list[FirewallHit]] = collections.defaultdict(list)
        for h in hits:
            by_ip[h.src].append(h)
        top_ips = sorted(by_ip.items(), key=lambda kv: -len(kv[1]))[:7]
        ports = collections.Counter(h.dport for h in hits if h.dport)
        return {
            "total": len(hits),
            "ips": len(by_ip),
            "top_ips": [(ip, len(hs), len({h.dport for h in hs if h.dport}), max(h.ts for h in hs)) for ip, hs in top_ips],
            "top_ports": ports.most_common(7),
            "truncated": len(self._hits) == self.MAX_HITS,
        }

    # -- background reading -----------------------------------------------------------

    def select_source(self) -> Any:
        mode = self.cfg.source
        files = [f for f in (self.cfg.log_file, "/var/log/kern.log") if f]
        if mode == "auto":
            mode = "journal" if journal_available() and journal_readable() else "file"
        if mode == "journal":
            return JournalSource(self._storage, self._stop, ["_TRANSPORT=kernel"], parse_firewall_message,
                                 key="fw", label="firewall")
        path = next((f for f in files if os.access(f, os.R_OK)), files[0])
        return FileSource(path, self._storage, self._stop, parse_firewall_line, key="fw")

    def start(self, source_factory: Callable[[], Any] | None = None) -> None:
        self._source = (source_factory or self.select_source)()
        self.source_name = self._source.name
        threading.Thread(target=self._run, name="fw-watch", daemon=True).start()

    @property
    def source_error(self) -> str:
        return getattr(self._source, "error", "") if self._source else ""

    def _run(self) -> None:
        try:
            for hit in self._source.lines():
                self.handle(hit)
        except Exception:
            log.exception("firewall watcher crashed")

    def stop(self) -> None:
        self._stop.set()
        if self._source:
            self._source.close()


# --- inbound connections ------------------------------------------------------------


def _decode_addr(hex_addr: str) -> str:
    ip_hex, port_hex = hex_addr.split(":")
    raw = bytes.fromhex(ip_hex)
    if len(raw) == 4:
        ip = ipaddress.IPv4Address(raw[::-1])
    else:  # IPv6: four 32-bit words, each in host (little-endian) byte order
        ip6 = ipaddress.IPv6Address(b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4)))
        ip = ip6.ipv4_mapped or ip6  # type: ignore[assignment]
    return f"{ip}:{int(port_hex, 16)}"


@dataclass
class Socket:
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    state: str  # hex state: 01 ESTABLISHED, 0A LISTEN


def parse_proc_net_tcp(text: str) -> list[Socket]:
    result = []
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 4:
            continue
        try:
            local, remote = _decode_addr(parts[1]), _decode_addr(parts[2])
        except ValueError:
            continue
        lip, _, lport = local.rpartition(":")
        rip, _, rport = remote.rpartition(":")
        result.append(Socket(lip, int(lport), rip, int(rport), parts[3]))
    return result


class ConnectionMonitor:
    name = "connections"

    def __init__(self, cfg: ConnectionsSection, bus: EventBus, trusted_networks: list[str], proc: str = "/proc"):
        self.cfg = cfg
        self.interval = cfg.interval
        self._bus = bus
        self._proc = proc
        self._trusted = [ipaddress.ip_network(n, strict=False) for n in trusted_networks]
        self._seen: dict[tuple[str, int], float] = {}
        self.listening: set[int] = set()
        self.last_inbound: list[tuple[float, str, int]] = []

    def sockets(self) -> list[Socket]:
        result = []
        for name in ("tcp", "tcp6"):
            try:
                with open(os.path.join(self._proc, "net", name), encoding="utf-8") as fh:
                    result += parse_proc_net_tcp(fh.read())
            except OSError:
                continue
        return result

    def _interesting_remote(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if addr.is_loopback or addr.is_unspecified or addr.is_link_local:
            return False
        if not self.cfg.notify_private and addr.is_private:
            return False
        return not any(addr in net for net in self._trusted)

    def tick(self) -> None:
        sockets = self.sockets()
        watched = set(self.cfg.ports)
        self.listening = {s.local_port for s in sockets if s.state == "0A" and s.local_port in watched}
        now = time.time()
        for (ip, port), ts in list(self._seen.items()):
            if now - ts > self.cfg.cooldown:
                del self._seen[(ip, port)]
        for s in sockets:
            if s.state != "01" or s.local_port not in self.listening or not self._interesting_remote(s.remote_ip):
                continue
            key = (s.remote_ip, s.local_port)
            if key in self._seen:
                continue
            self._seen[key] = now
            self.last_inbound = ([(now, s.remote_ip, s.local_port)] + self.last_inbound)[:20]
            self._bus.emit(Event(
                "security", "warning", "inbound_connection", f"Внешнее подключение к порту {port_label(s.local_port)}",
                f"С адреса <code>{esc(s.remote_ip)}</code> установлено соединение с "
                f"<code>{esc(s.local_ip)}:{s.local_port}</code>.\nЕсли этот сервис не должен быть доступен из интернета, "
                "закройте порт файрволом.",
                data={"ip": s.remote_ip, "port": s.local_port}))
