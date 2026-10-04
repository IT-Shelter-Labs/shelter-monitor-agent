"""Threshold alerts for CPU, memory, swap, disks, load average and temperature."""

from __future__ import annotations

import logging

from shelter_monitor.agent.collectors.system import CpuSampler, SystemCollector
from shelter_monitor.agent.config import MonitorSection
from shelter_monitor.agent.events import AlertTracker, Event
from shelter_monitor.util import esc, fmt_bytes, fmt_duration

log = logging.getLogger(__name__)


def _resolved(title: str, category: str = "system"):
    def make(duration: float) -> Event:
        return Event(category, "info", "resolved", f"✅ {title}", f"Длительность проблемы: {fmt_duration(duration)}",
                     data={"notify": True})
    return make


class ResourceMonitor:
    name = "resources"

    def __init__(self, cfg: MonitorSection, collector: SystemCollector, tracker: AlertTracker):
        self.cfg = cfg
        self.interval = cfg.interval
        self._collector = collector
        self._tracker = tracker
        self._cpu = CpuSampler(collector)
        self._cpu_high_streak = 0
        self._load_high_streak = 0

    def tick(self) -> None:
        cfg = self.cfg
        # CPU: must stay above the threshold for `cpu_sustain` consecutive checks.
        cpu = self._cpu.percent()
        self._cpu_high_streak = self._cpu_high_streak + 1 if cpu >= cfg.cpu_percent else 0
        self._tracker.check(
            "cpu",
            self._cpu_high_streak >= cfg.cpu_sustain,
            lambda: Event("system", "warning", "cpu_high", "Высокая загрузка CPU",
                          f"CPU: <b>{cpu:.0f}%</b> дольше {fmt_duration(cfg.cpu_sustain * cfg.interval)} "
                          f"(порог {cfg.cpu_percent:.0f}%)", data={"cpu_percent": cpu}),
            _resolved("Загрузка CPU нормализовалась"),
        )

        cores = self._collector.cpu_count()
        load = self._collector.load()
        per_core = load[1] / cores
        self._load_high_streak = self._load_high_streak + 1 if per_core >= cfg.load_per_cpu else 0
        self._tracker.check(
            "load",
            self._load_high_streak >= 2,
            lambda: Event("system", "warning", "load_high", "Высокий load average",
                          f"Load: <b>{load[0]:.2f} / {load[1]:.2f} / {load[2]:.2f}</b> (ядер: {cores}) "
                          f"(порог {cfg.load_per_cpu:g} на ядро)", data={"load": load}),
            _resolved("Load average нормализовался"),
        )

        mem = self._collector.memory()
        self._tracker.check(
            "memory",
            mem.percent >= cfg.memory_percent,
            lambda: Event("system", "critical" if mem.percent >= 97 else "warning", "memory_high", "Мало оперативной памяти",
                          f"RAM: <b>{mem.percent:.0f}%</b> ({fmt_bytes(mem.used)} из {fmt_bytes(mem.total)}), "
                          f"доступно {fmt_bytes(mem.available)}", data={"mem_percent": mem.percent}),
            _resolved("Память в норме"),
        )
        self._tracker.check(
            "swap",
            mem.swap_total > 0 and mem.swap_percent >= cfg.swap_percent,
            lambda: Event("system", "warning", "swap_high", "Активно используется swap",
                          f"Swap: <b>{mem.swap_percent:.0f}%</b> ({fmt_bytes(mem.swap_used)} из {fmt_bytes(mem.swap_total)})",
                          data={"swap_percent": mem.swap_percent}),
            _resolved("Использование swap в норме"),
        )

        disks = self._collector.disks(cfg.disk_mounts, cfg.disk_ignore)
        seen = set()
        for disk in disks:
            key = f"disk:{disk.mount}"
            seen.add(key)
            pct = disk.percent
            sev = "critical" if pct >= cfg.disk_critical_percent else "warning"
            self._tracker.check(
                key,
                pct >= cfg.disk_percent,
                lambda d=disk, s=sev: Event(
                    "system", s, "disk_full", f"Заканчивается место: {d.mount}",
                    f"Занято <b>{d.percent:.0f}%</b>, свободно {fmt_bytes(d.free)} из {fmt_bytes(d.total)}\n"
                    f"<code>{esc(d.device)}</code> ({esc(d.fstype)})", data={"mount": d.mount, "percent": d.percent}),
                _resolved(f"Место на {disk.mount} в норме"),
            )
        for alert in self._tracker.active():  # mount disappeared -> drop stale alert silently
            if alert.key.startswith("disk:") and alert.key not in seen:
                self._tracker.resolve(alert.key)

        temp = self._collector.temperature()
        self._tracker.check(
            "temperature",
            temp is not None and temp >= cfg.temperature_c,
            lambda: Event("system", "critical" if (temp or 0) >= cfg.temperature_c + 10 else "warning", "temperature_high",
                          "Перегрев", f"Температура: <b>{temp:.0f}°C</b> (порог {cfg.temperature_c:.0f}°C)",
                          data={"temperature": temp}),
            _resolved("Температура в норме"),
        )
