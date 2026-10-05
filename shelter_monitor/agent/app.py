"""Agent wiring: builds all components from the config and runs them."""

from __future__ import annotations

import logging
import os
import signal
import threading
import time
from typing import Any

from shelter_monitor import __version__
from shelter_monitor.agent.actions import ActionManager
from shelter_monitor.agent.bot.bot import Bot
from shelter_monitor.agent.collectors.docker import DockerClient
from shelter_monitor.agent.collectors.system import CpuSampler, NetSampler, Snapshot, SystemCollector, take_snapshot
from shelter_monitor.agent.collectors.systemd import SystemdClient
from shelter_monitor.agent.config import Config, normalize_unit
from shelter_monitor.agent.events import AlertTracker, Event, EventBus
from shelter_monitor.agent.heartbeat import HeartbeatSender
from shelter_monitor.agent.lan import LANScanner, lan_supported
from shelter_monitor.agent.monitors.connectivity import ConnectivityMonitor
from shelter_monitor.agent.monitors.docker_watch import DockerMonitor
from shelter_monitor.agent.monitors.resources import ResourceMonitor
from shelter_monitor.agent.monitors.services_watch import ServicesMonitor
from shelter_monitor.agent.notifier import NotificationSettings, Notifier
from shelter_monitor.agent.scheduler import PeriodicTask
from shelter_monitor.agent.ssh import SSHWatcher
from shelter_monitor.agent.storage import Storage
from shelter_monitor.telegram import Outbox, TelegramAPI
from shelter_monitor.util import fmt_duration

log = logging.getLogger(__name__)


class Agent:
    def __init__(self, cfg: Config, api: TelegramAPI | None = None, storage: Storage | None = None):
        self.cfg = cfg
        self.system = SystemCollector(host_root=cfg.agent.host_root)
        self.host = cfg.agent.name or self.system.hostname()
        self.started_at = time.time()
        self.storage = storage or Storage(os.path.join(cfg.agent.data_dir, "agent.db"))
        self.api = api or TelegramAPI(cfg.telegram.token, cfg.telegram.api_url, cfg.telegram.proxy)
        self.outbox = Outbox(self.api, max_attempts=30)
        self.bus = EventBus(self.storage, self.host)
        self.settings = NotificationSettings(self.storage)
        self.notifier = Notifier(
            self.outbox, cfg.notify_chats, self.host, self.settings,
            cfg.notifications.min_severity, cfg.notifications.mute_allows_critical, cfg.notifications.silent_info,
        )
        self.bus.subscribe(self.notifier)
        self.tracker = AlertTracker(self.bus)

        self.systemd = SystemdClient()
        self.docker = DockerClient(cfg.docker.socket) if cfg.docker.enabled else None
        self._snapshot_lock = threading.Lock()
        self._cpu = CpuSampler(self.system)
        self._net = NetSampler(self.system, cfg.monitor.net_interfaces)
        self.boot_id = self.system.boot_id()

        self.services_units = [normalize_unit(u) for u in cfg.services.units] if cfg.services.enabled else []
        monitors: list[Any] = [ResourceMonitor(cfg.monitor, self.system, self.tracker)]
        if self.docker is not None:
            monitors.append(DockerMonitor(cfg.docker, self.docker, self.tracker, self.bus))
        if cfg.services.enabled:
            monitors.append(ServicesMonitor(cfg.services, self.systemd, self.tracker))
        self.connectivity = ConnectivityMonitor(cfg.connectivity, self.tracker) if cfg.connectivity.enabled else None
        if self.connectivity:
            monitors.append(self.connectivity)
        self.lan = LANScanner(cfg.lan, self.system, self.storage, self.bus) if cfg.lan.enabled and lan_supported() else None
        if self.lan:
            monitors.append(self.lan)
        self.heartbeat = None
        if cfg.heartbeat.enabled:
            self.heartbeat = HeartbeatSender(cfg.heartbeat, self.host, self.boot_id, self._heartbeat_summary,
                                             lambda: len(self.tracker.active()))
            monitors.append(self.heartbeat)

        initial = {"lan": 20.0, "heartbeat": 2.0}
        self.tasks: dict[str, PeriodicTask] = {
            m.name: PeriodicTask(m.name, m.interval, m.tick, initial.get(m.name)) for m in monitors
        }
        self.tasks["maintenance"] = PeriodicTask("maintenance", 6 * 3600, self._maintenance, 60)
        self.health_file = os.path.join(cfg.agent.data_dir, "health")
        self.tasks["health"] = PeriodicTask("health", 30, self._touch_health, 10)

        self.ssh = SSHWatcher(cfg.ssh, self.storage, self.bus) if cfg.ssh.enabled else None
        self.actions = ActionManager(cfg.actions, self.bus, self.docker, enabled=cfg.telegram.allow_actions)
        self.bot = Bot(self, self.api, cfg.telegram.admin_ids)
        self._stop = threading.Event()

    # -- data used by views / heartbeat ------------------------------------------------

    def snapshot(self, net_window: float = 0.0) -> Snapshot:
        with self._snapshot_lock:
            if net_window:
                self._net.rates()
                time.sleep(net_window)
            return take_snapshot(self.system, self._cpu, self._net, self.cfg.monitor.disk_mounts, self.cfg.monitor.disk_ignore)

    def _heartbeat_summary(self) -> dict[str, Any]:
        return self.snapshot().summary()

    def run_checks(self) -> None:
        for name, task in self.tasks.items():
            if name not in ("maintenance", "heartbeat", "health"):
                task.run_once()

    def trigger_task(self, name: str) -> bool:
        task = self.tasks.get(name)
        if task is None:
            return False
        task.trigger()
        return True

    def _maintenance(self) -> None:
        self.storage.cleanup(self.cfg.agent.retention_days)

    def _touch_health(self) -> None:
        """Liveness marker for `shelter-agent healthcheck` (Docker HEALTHCHECK)."""
        if not self.bot.is_alive():
            log.error("telegram bot thread is not running")
            return
        try:
            with open(self.health_file, "w", encoding="utf-8") as fh:
                fh.write(f"{time.time():.0f}\n")
        except OSError as exc:
            log.warning("cannot write %s: %s", self.health_file, exc)

    # -- lifecycle -------------------------------------------------------------------

    def _startup_events(self) -> None:
        previous_boot = self.storage.kv_get("agent.boot_id")
        uptime = self.system.uptime()
        if previous_boot and self.boot_id and previous_boot != self.boot_id:
            self.bus.emit(Event("system", "warning", "server_rebooted", "Сервер был перезагружен",
                                f"Аптайм: {fmt_duration(uptime)}", data={"uptime": uptime}))
        if self.boot_id:
            self.storage.kv_set("agent.boot_id", self.boot_id)
        parts = [f"Версия {__version__}"]
        if self.ssh:
            parts.append(f"SSH: {self.ssh.source_name}")
        parts.append("Мониторы: " + ", ".join(n for n in self.tasks if n not in ("maintenance", "health")))
        self.bus.emit(Event("agent", "info", "agent_started", "Агент мониторинга запущен", "\n".join(parts),
                            data={"notify": True}))

    def start(self) -> None:
        log.info("starting Shelter Monitor Agent %s on %s", __version__, self.host)
        self.outbox.start()
        if self.ssh:
            self.ssh.start()
        self._startup_events()
        for task in self.tasks.values():
            task.start()
        self.bot.start()

    def stop(self) -> None:
        log.info("stopping agent")
        self._stop.set()
        self.bot.stop()
        for task in self.tasks.values():
            task.stop()
        if self.ssh:
            self.ssh.stop()
        self.bus.emit(Event("agent", "info", "agent_stopped", "Агент мониторинга остановлен",
                            f"Работал {fmt_duration(time.time() - self.started_at)}", data={"notify": True}))
        self.outbox.stop(flush_timeout=5)
        self.storage.close()

    def run_forever(self) -> None:
        def on_signal(signum: int, _frame: Any) -> None:
            log.info("received signal %s", signum)
            self._stop.set()

        signal.signal(signal.SIGTERM, on_signal)
        signal.signal(signal.SIGINT, on_signal)
        self.start()
        try:
            while not self._stop.wait(3600):
                pass
        finally:
            self.stop()
