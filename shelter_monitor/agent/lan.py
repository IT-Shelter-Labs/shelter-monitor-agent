"""Discovery of new devices in the local network.

Unprivileged approach: a tiny UDP datagram is sent to every address of the local
subnet, which makes the kernel resolve each address via ARP. Responding hosts then
show up in the neighbour table (/proc/net/arp), which is read afterwards. No raw
sockets, root or nmap required.
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import logging
import os
import socket
import time
from dataclasses import dataclass
from typing import Any

from shelter_monitor.agent.collectors.system import SystemCollector
from shelter_monitor.agent.config import LANSection
from shelter_monitor.agent.events import Event, EventBus
from shelter_monitor.agent.runtime import uses_host_network
from shelter_monitor.util import esc

log = logging.getLogger(__name__)

_DNS_POOL = concurrent.futures.ThreadPoolExecutor(max_workers=2, thread_name_prefix="rdns")


@dataclass
class Neighbor:
    ip: str
    mac: str
    iface: str


def parse_proc_arp(text: str) -> list[Neighbor]:
    result = []
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 6:
            continue
        ip, flags, mac, iface = parts[0], int(parts[2], 16), parts[3].lower(), parts[5]
        if not flags & 0x2 or mac == "00:00:00:00:00:00":  # incomplete entry
            continue
        result.append(Neighbor(ip, mac, iface))
    return result


def is_random_mac(mac: str) -> bool:
    """Locally administered bit set: phones/laptops with MAC randomisation."""
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except ValueError:
        return False


def reverse_dns(ip: str, timeout: float = 2.0) -> str:
    future = _DNS_POOL.submit(socket.gethostbyaddr, ip)
    try:
        return future.result(timeout=timeout)[0]
    except Exception:
        return ""


def describe_device(ip: str, mac: str, hostname: str = "", iface: str = "") -> str:
    """HTML card of a device, shared by notifications and the bot."""
    lines = [f"IP: <code>{esc(ip)}</code>", f"MAC: <code>{esc(mac)}</code>"]
    if hostname:
        lines.append(f"Имя: {esc(hostname)}")
    if is_random_mac(mac):
        lines.append("🎲 Случайный (локально назначенный) MAC — так выглядят телефоны и ноутбуки "
                     "с приватным адресом, а также виртуальные машины и контейнеры")
    if iface:
        lines.append(f"Интерфейс: {esc(iface)}")
    return "\n".join(lines)


def device_buttons(mac: str, trusted: bool) -> list[list[tuple[str, str]]]:
    first = ("🚫 Снять доверие", f"dev:untrust:{mac}") if trusted else ("✅ Доверять", f"dev:trust:{mac}")
    return [[first, ("🗑 Забыть", f"dev:forget:{mac}")], [("📋 Все устройства", "o:devices")]]


class LANScanner:
    name = "lan"
    DOCKER_NETS_TTL = 300

    def __init__(self, cfg: LANSection, collector: SystemCollector, storage: Any, bus: EventBus,
                 arp_path: str = "/proc/net/arp", docker: Any = None):
        self.cfg = cfg
        self.interval = cfg.interval
        self._collector = collector
        self._storage = storage
        self._bus = bus
        self._arp_path = arp_path
        self._docker = docker
        self._docker_nets: list[ipaddress.IPv4Network] = []
        self._docker_nets_ts = 0.0
        self.last_scan: float = 0.0
        self.last_subnets: list[str] = []
        self.disabled_reason = ""

    def docker_networks(self) -> list[ipaddress.IPv4Network]:
        """Subnets of Docker networks: containers there are not LAN devices."""
        if self._docker is None or not self._docker.available():
            return []
        if time.time() - self._docker_nets_ts > self.DOCKER_NETS_TTL:
            try:
                self._docker_nets = [ipaddress.IPv4Network(sub, strict=False) for _, sub in self._docker.networks()]
                self._docker_nets_ts = time.time()
            except Exception as exc:  # DockerError, ValueError
                log.debug("cannot list docker networks: %s", exc)
        return self._docker_nets

    def subnets(self) -> list[tuple[str, ipaddress.IPv4Network]]:
        self.disabled_reason = ""
        if self.cfg.subnets:
            nets = [ipaddress.IPv4Network(n, strict=False) for n in self.cfg.subnets]
            return [("", n) for n in nets]
        if not uses_host_network():
            self.disabled_reason = ("агент запущен в контейнере со своей сетью Docker и видит только соседние "
                                    "контейнеры. Добавьте network_mode: host в docker-compose.yml")
            return []
        default = self._collector.default_route()
        docker_nets = self.docker_networks()
        result = []
        skipped_docker = []
        for iface, cidr in self._collector.ipv4_routes():
            if SystemCollector.is_virtual_iface(iface):
                continue
            if default and iface != default[0]:
                continue
            net = ipaddress.IPv4Network(cidr, strict=False)
            if not net.is_private or net.prefixlen >= 31:
                continue
            if any(net.overlaps(d) for d in docker_nets):
                skipped_docker.append(str(net))
                continue
            result.append((iface, net))
        if not result and skipped_docker:
            self.disabled_reason = (f"подсеть {', '.join(skipped_docker)} принадлежит Docker — в ней контейнеры, "
                                    "а не устройства LAN. Запустите агента с network_mode: host")
        return result

    def probe(self, net: ipaddress.IPv4Network) -> None:
        hosts = list(net.hosts())
        if len(hosts) > self.cfg.max_hosts:
            log.warning("subnet %s has %d hosts (> max_hosts=%d), skipping active probe", net, len(hosts), self.cfg.max_hosts)
            return
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        try:
            for i, host in enumerate(hosts):
                try:
                    sock.sendto(b"", (str(host), 9))  # discard port; the ARP request is what matters
                except OSError:
                    pass
                if i % 64 == 63:
                    time.sleep(0.05)  # be gentle with the network
        finally:
            sock.close()

    def neighbors(self) -> list[Neighbor]:
        try:
            with open(self._arp_path, encoding="utf-8") as fh:
                return parse_proc_arp(fh.read())
        except OSError as exc:
            log.warning("cannot read %s: %s", self._arp_path, exc)
            return []

    def scan(self) -> list[Neighbor]:
        subnets = self.subnets()
        self.last_subnets = [str(n) for _, n in subnets]
        if not subnets:
            if self.disabled_reason:
                log.info("LAN discovery disabled: %s", self.disabled_reason)
            return []
        if self.cfg.active_probe:
            for _, net in subnets:
                self.probe(net)
            time.sleep(3)  # let ARP replies arrive
        found = []
        for nb in self.neighbors():
            addr = ipaddress.IPv4Address(nb.ip)
            if any(addr in net and (not iface or iface == nb.iface) for iface, net in subnets):
                found.append(nb)
        return found

    def purge_docker_devices(self) -> int:
        """Forget devices recorded from Docker networks (by older versions or a bridged container)."""
        nets = self.docker_networks()
        if not nets and not self.disabled_reason:
            return 0
        removed = 0
        for dev in self._storage.list_devices():
            try:
                addr = ipaddress.IPv4Address(dev.ip)
            except ValueError:
                continue
            if any(addr in n for n in nets):
                removed += int(self._storage.delete_device(dev.mac))
        if removed:
            log.info("forgot %d devices from Docker networks", removed)
        return removed

    def tick(self) -> None:
        neighbors = self.scan()
        self.purge_docker_devices()
        now = time.time()
        self.last_scan = now
        if not neighbors:
            return
        baseline = self.cfg.baseline_first_scan and self._storage.device_count() == 0
        new_devices = []
        for nb in neighbors:
            is_new = self._storage.upsert_device(nb.mac, nb.ip, "", nb.iface, now, trusted=baseline)
            if is_new:
                new_devices.append(nb)
        if baseline:
            self._bus.emit(Event(
                "lan", "info", "lan_baseline", "Сеть просканирована впервые",
                f"Найдено устройств: <b>{len(neighbors)}</b> в {', '.join(self.last_subnets)}.\n"
                "Они отмечены как известные; о новых устройствах будут приходить уведомления.",
                data={"count": len(neighbors), "notify": True}, buttons=[[("📋 Все устройства", "o:devices")]]))
            return
        for nb in new_devices:
            hostname = reverse_dns(nb.ip)
            if hostname:
                self._storage.upsert_device(nb.mac, nb.ip, hostname, nb.iface, now)
            self._bus.emit(Event(
                "lan", "warning", "lan_new_device", "Новое устройство в локальной сети",
                describe_device(nb.ip, nb.mac, hostname, nb.iface),
                data={"mac": nb.mac, "ip": nb.ip, "hostname": hostname, "notify": True},
                buttons=device_buttons(nb.mac, trusted=False)))


def lan_supported() -> bool:
    return os.path.exists("/proc/net/arp")
