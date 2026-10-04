"""systemd service monitoring: configured units + any unit entering the failed state."""

from __future__ import annotations

import logging

from shelter_monitor.agent.collectors.systemd import SystemdClient
from shelter_monitor.agent.config import ServicesSection, normalize_unit
from shelter_monitor.agent.events import AlertTracker, Event
from shelter_monitor.util import esc, fmt_duration

log = logging.getLogger(__name__)


class ServicesMonitor:
    name = "services"

    def __init__(self, cfg: ServicesSection, client: SystemdClient, tracker: AlertTracker):
        self.cfg = cfg
        self.interval = cfg.interval
        self.units = [normalize_unit(u) for u in cfg.units]
        self._client = client
        self._tracker = tracker
        self._missing_logged: set[str] = set()

    def tick(self) -> None:
        if not self._client.available():
            return
        for unit in self._client.status(self.units):
            if not unit.exists:
                if unit.name not in self._missing_logged:
                    log.info("unit %s not installed, skipping", unit.name)
                    self._missing_logged.add(unit.name)
                continue
            sev = "critical" if unit.active_state == "failed" else "warning"
            self._tracker.check(
                f"svc:{unit.name}", not unit.ok,
                lambda u=unit, sev=sev: Event(
                    "services", sev, "service_down", f"Сервис не работает: {u.name}",
                    f"Состояние: <b>{esc(u.active_state)}</b> ({esc(u.sub_state)})\n{esc(u.description)}",
                    data={"unit": u.name, "state": u.active_state}),
                lambda d, u=unit: Event("services", "info", "resolved", f"✅ Сервис снова работает: {u.name}",
                                        f"Простой: {fmt_duration(d)}", data={"notify": True}),
            )

        if self.cfg.watch_failed_units:
            failed = set(self._client.failed_units()) - set(self.units)
            for name in failed:
                self._tracker.check(
                    f"failed:{name}", True,
                    lambda n=name: Event("services", "warning", "unit_failed", f"Юнит в состоянии failed: {n}",
                                         f"Проверьте: <code>systemctl status {esc(n)}</code>", data={"unit": n}),
                )
            for alert in self._tracker.active():
                if alert.key.startswith("failed:") and alert.key[7:] not in failed:
                    self._tracker.resolve(
                        alert.key,
                        lambda d, n=alert.key[7:]: Event("services", "info", "resolved", f"✅ Юнит восстановлен: {n}",
                                                         data={"notify": True}),
                    )
