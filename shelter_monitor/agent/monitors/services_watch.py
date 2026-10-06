"""systemd service monitoring: configured units + any unit entering the failed state."""

from __future__ import annotations

import logging
from typing import Callable

from shelter_monitor.agent.collectors.systemd import ServiceProbe
from shelter_monitor.agent.config import ServicesSection, normalize_unit
from shelter_monitor.agent.events import AlertTracker, Event
from shelter_monitor.util import esc, fmt_duration

log = logging.getLogger(__name__)

ButtonsFn = Callable[[str], list[list[tuple[str, str]]]]


class ServicesMonitor:
    name = "services"

    def __init__(self, cfg: ServicesSection, probe: ServiceProbe, tracker: AlertTracker, buttons: ButtonsFn | None = None):
        self.cfg = cfg
        self.interval = cfg.interval
        self.units = [normalize_unit(u) for u in cfg.units]
        self._probe = probe
        self._tracker = tracker
        self._buttons = buttons or (lambda unit: [])
        self._missing_logged: set[str] = set()

    def tick(self) -> None:
        statuses, source, error = self._probe.status(self.units)
        # Losing access to systemd is itself a problem worth one notification.
        self._tracker.check(
            "svc:probe", source != "systemd",
            lambda: Event("services", "warning", "systemd_unreachable", "Нет доступа к systemd хоста",
                          f"Ошибка: <code>{esc(error)}</code>\n"
                          + ("Статус сервисов определяется приблизительно, по процессам; уведомления о сервисах "
                             "отключены. " if source == "processes" else "")
                          + "Подробности: /diag", data={"error": error}),
            lambda d: Event("services", "info", "resolved", "✅ Доступ к systemd восстановлен", data={"notify": True}),
        )
        if source != "systemd":
            return  # the process fallback is too approximate to alert on

        for unit in statuses:
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
                    data={"unit": u.name, "state": u.active_state}, buttons=self._buttons(u.name)),
                lambda d, u=unit: Event("services", "info", "resolved", f"✅ Сервис снова работает: {u.name}",
                                        f"Простой: {fmt_duration(d)}", data={"notify": True}),
            )

        if self.cfg.watch_failed_units:
            failed = set(self._probe.failed_units()) - set(self.units)
            for name in failed:
                self._tracker.check(
                    f"failed:{name}", True,
                    lambda n=name: Event("services", "warning", "unit_failed", f"Юнит в состоянии failed: {n}",
                                         f"Проверьте: <code>systemctl status {esc(n)}</code>", data={"unit": n},
                                         buttons=self._buttons(n)),
                )
            for alert in self._tracker.active():
                if alert.key.startswith("failed:") and alert.key[7:] not in failed:
                    self._tracker.resolve(
                        alert.key,
                        lambda d, n=alert.key[7:]: Event("services", "info", "resolved", f"✅ Юнит восстановлен: {n}",
                                                         data={"notify": True}),
                    )
