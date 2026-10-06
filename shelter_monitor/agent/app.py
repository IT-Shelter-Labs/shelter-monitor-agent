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
from shelter_monitor.agent.collectors.systemd import ServiceProbe, SystemdClient
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
from shelter_monitor.agent.security import ConnectionMonitor, FirewallWatcher
from shelter_monitor.agent.ssh import SSHWatcher
from shelter_monitor.agent.storage import Storage
from shelter_monitor.telegram import Outbox, TelegramAPI
from shelter_monitor.util import esc, fmt_duration, fmt_ts

log = logging.getLogger(__name__)

HEALTH_INTERVAL = 30
DOWNTIME_REPORT_THRESHOLD = 180  # seconds without a liveness mark worth reporting
NOT_CHECKS = ("maintenance", "heartbeat", "health")  # tasks that are not "checks"


class Agent:
    def __init__(self, cfg: Config, api: TelegramAPI | None = None, storage: Storage | None = None):
        self.cfg = cfg
        self.system = SystemCollector(host_root=cfg.agent.host_root)
        self.host = cfg.agent.name or self.system.hostname()
        self.started_at = time.time()
        self.restart_requested = False
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
        self.service_probe = ServiceProbe(self.systemd, self.system.host_root)
        self.docker = DockerClient(cfg.docker.socket) if cfg.docker.enabled else None
        self._snapshot_lock = threading.Lock()
        self._cpu = CpuSampler(self.system)
        self._net = NetSampler(self.system, cfg.monitor.net_interfaces)
        self.boot_id = self.system.boot_id()
        self.services_units = [normalize_unit(u) for u in cfg.services.units] if cfg.services.enabled else []
        self.actions = ActionManager(cfg.actions, self.bus, self.docker, enabled=cfg.telegram.allow_actions,
                                     monitored_units=self.services_units, restart_agent=self.request_restart)

        disk_buttons = [[("🧹 Очистить Docker", "a:dp:")]] if self.actions.allowed("dp") else []
        monitors: list[Any] = [ResourceMonitor(cfg.monitor, self.system, self.tracker, disk_buttons)]
        if self.docker is not None:
            monitors.append(DockerMonitor(cfg.docker, self.docker, self.tracker, self.bus, self.actions.container_buttons))
        if cfg.services.enabled:
            monitors.append(ServicesMonitor(cfg.services, self.service_probe, self.tracker, self.actions.service_buttons))
        self.connectivity = ConnectivityMonitor(cfg.connectivity, self.tracker) if cfg.connectivity.enabled else None
        if self.connectivity:
            monitors.append(self.connectivity)
        self.lan = None
        if cfg.lan.enabled and lan_supported():
            self.lan = LANScanner(cfg.lan, self.system, self.storage, self.bus, docker=self.docker)
            monitors.append(self.lan)
        self.connections = None
        if cfg.connections.enabled:
            self.connections = ConnectionMonitor(cfg.connections, self.bus, cfg.ssh.trusted_networks)
            monitors.append(self.connections)
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
        self.tasks["health"] = PeriodicTask("health", HEALTH_INTERVAL, self._touch_health, 10)

        self.ssh = SSHWatcher(cfg.ssh, self.storage, self.bus) if cfg.ssh.enabled else None
        self.firewall = FirewallWatcher(cfg.firewall, self.storage, self.bus) if cfg.firewall.enabled else None
        self.bot = Bot(self, self.api, cfg.telegram.admin_ids)
        self._stop = threading.Event()
        self._checks_lock = threading.Lock()

    # -- data used by views / heartbeat ------------------------------------------------

    def snapshot(self, net_window: float = 0.0) -> Snapshot:
        with self._snapshot_lock:
            if net_window:
                self._net.rates()
                time.sleep(net_window)
            return take_snapshot(self.system, self._cpu, self._net, self.cfg.monitor.disk_mounts, self.cfg.monitor.disk_ignore)

    def _heartbeat_summary(self) -> dict[str, Any]:
        return self.snapshot().summary()

    def run_checks(self) -> dict[str, Any]:
        """Run every check right now. Returns what changed (new / resolved problems)."""
        if not self._checks_lock.acquire(blocking=False):
            return {"busy": True, "new": [], "resolved": [], "active": self.tracker.active(), "took": 0.0}
        try:
            started = time.time()
            before = {a.key: a for a in self.tracker.active()}
            for name, task in self.tasks.items():
                if name not in NOT_CHECKS:
                    task.run_once()
            after = {a.key: a for a in self.tracker.active()}
            return {
                "busy": False,
                "new": [a for k, a in after.items() if k not in before],
                "resolved": [a for k, a in before.items() if k not in after],
                "active": list(after.values()),
                "took": time.time() - started,
            }
        finally:
            self._checks_lock.release()

    def trigger_task(self, name: str) -> bool:
        task = self.tasks.get(name)
        if task is None:
            return False
        task.trigger()
        return True

    def run_task(self, name: str) -> bool:
        task = self.tasks.get(name)
        if task is None:
            return False
        task.run_once()
        return True

    def request_restart(self) -> None:
        log.warning("restart requested from Telegram")
        self.restart_requested = True
        self._stop.set()

    def _maintenance(self) -> None:
        self.storage.cleanup(self.cfg.agent.retention_days)

    def _touch_health(self) -> None:
        """Liveness marker for `shelter-agent healthcheck` (Docker HEALTHCHECK) and the downtime report."""
        if not self.bot.is_alive():
            log.error("telegram bot thread is not running")
            return
        now = time.time()
        self.storage.kv_set("agent.last_alive", f"{now:.0f}")
        try:
            with open(self.health_file, "w", encoding="utf-8") as fh:
                fh.write(f"{now:.0f}\n")
        except OSError as exc:
            log.warning("cannot write %s: %s", self.health_file, exc)

    # -- lifecycle -------------------------------------------------------------------

    def _downtime_report(self) -> Event | None:
        """After a start, tell what happened while the agent was not running.

        Without any external service this detects power loss / crashes post factum:
        the last liveness mark, the clean-stop flag and the boot id tell the story.
        """
        now = time.time()
        last_alive = float(self.storage.kv_get("agent.last_alive", "0") or 0)
        clean_stop = float(self.storage.kv_get("agent.clean_stop", "0") or 0)
        previous_boot = self.storage.kv_get("agent.boot_id")
        uptime = self.system.uptime()
        boot_time = now - uptime
        rebooted = bool(previous_boot and self.boot_id and previous_boot != self.boot_id)
        if not last_alive:
            return None
        stopped_cleanly = clean_stop >= last_alive
        if rebooted:
            down_for = max(0.0, boot_time - max(last_alive, clean_stop))
            if stopped_cleanly:
                title, sev = "Сервер был перезагружен", "warning"
                cause = "Агент был штатно остановлен перед перезагрузкой."
            else:
                title, sev = "Сервер был выключен или завис", "critical"
                cause = "Штатной остановки не было: вероятно, пропало питание, произошёл kernel panic или жёсткий сброс."
            return Event("system", sev, "server_rebooted", title,
                         f"{cause}\nПоследний признак жизни: {fmt_ts(max(last_alive, clean_stop))}\n"
                         f"Загрузка системы: {fmt_ts(boot_time)}\nСервер не работал примерно: <b>{fmt_duration(down_for)}</b>",
                         data={"down_for": down_for, "clean": stopped_cleanly, "notify": True})
        gap = now - max(last_alive, clean_stop)
        if not stopped_cleanly and now - last_alive > DOWNTIME_REPORT_THRESHOLD:
            return Event("agent", "warning", "agent_crashed", "Агент мониторинга был аварийно остановлен",
                         f"Сервер не перезагружался, но агент не работал примерно {fmt_duration(now - last_alive)} "
                         f"(с {fmt_ts(last_alive)}).", data={"gap": gap, "notify": True})
        return None

    def _startup_events(self) -> None:
        report = self._downtime_report()
        if self.boot_id:
            self.storage.kv_set("agent.boot_id", self.boot_id)
        self.storage.kv_set("agent.last_alive", f"{time.time():.0f}")
        if report:
            self.bus.emit(report)

        from shelter_monitor.agent import diagnostics  # local import: diagnostics imports the app types

        if self.lan:
            self.lan.subnets()  # computes disabled_reason for the diagnostics below
        parts = [f"Версия {__version__}"]
        if self.ssh:
            parts.append(f"SSH-логи: {self.ssh.source_name}")
        parts.append("Мониторы: " + ", ".join(n for n in self.tasks if n not in ("maintenance", "health")))
        problems = diagnostics.problems(self)
        if problems:
            parts.append("\n⚠️ <b>Проблемы окружения:</b>")
            parts.extend(f"• {esc(p.title)}" for p in problems)
            parts.append("Подробности и как исправить: /diag")
        self.bus.emit(Event("agent", "warning" if problems else "info", "agent_started", "Агент мониторинга запущен",
                            "\n".join(parts), data={"notify": True},
                            buttons=[[("🩺 Диагностика", "o:diag"), ("📊 Статус", "o:status")]]))

    def start(self) -> None:
        log.info("starting Shelter Monitor Agent %s on %s", __version__, self.host)
        self.outbox.start()
        if self.ssh:
            self.ssh.start()
        if self.firewall:
            self.firewall.start()
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
        if self.firewall:
            self.firewall.stop()
        title = "Агент мониторинга перезапускается" if self.restart_requested else "Агент мониторинга остановлен"
        self.bus.emit(Event("agent", "info", "agent_stopped", title,
                            f"Работал {fmt_duration(time.time() - self.started_at)}", data={"notify": True}))
        self.storage.kv_set("agent.clean_stop", f"{time.time():.0f}")
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
