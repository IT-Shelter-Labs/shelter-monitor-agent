"""Docker container state tracking: stopped / restarting / unhealthy containers."""

from __future__ import annotations

import fnmatch
import logging
from typing import Callable

from shelter_monitor.agent.collectors.docker import Container, DockerClient, DockerError
from shelter_monitor.agent.config import DockerSection
from shelter_monitor.agent.events import AlertTracker, Event, EventBus
from shelter_monitor.util import esc, fmt_duration

log = logging.getLogger(__name__)


class DockerMonitor:
    name = "docker"

    def __init__(self, cfg: DockerSection, client: DockerClient, tracker: AlertTracker, bus: EventBus,
                 buttons: Callable[[str, str], list[list[tuple[str, str]]]] | None = None):
        self.cfg = cfg
        self._buttons = buttons or (lambda name, state: [])
        self.interval = cfg.interval
        self._client = client
        self._tracker = tracker
        self._bus = bus
        # Containers that were seen running: only these (and explicitly watched ones)
        # raise alerts when they stop. Intentionally stopped containers stay quiet.
        self._expected: set[str] = set()
        self._known: set[str] | None = None

    def _tracked(self, c: Container) -> bool:
        if any(fnmatch.fnmatch(c.name, p) for p in self.cfg.ignore):
            return False
        if self.cfg.watch:
            return any(fnmatch.fnmatch(c.name, p) for p in self.cfg.watch)
        return True

    def tick(self) -> None:
        if not self._client.available():
            return
        try:
            containers = self._client.containers()
        except DockerError as exc:
            error = str(exc)
            self._tracker.check(
                "docker:daemon", True,
                lambda: Event("docker", "critical", "docker_down", "Docker недоступен", esc(error)),
                lambda d: Event("docker", "info", "resolved", "✅ Docker снова доступен",
                                f"Недоступен был {fmt_duration(d)}", data={"notify": True}),
            )
            return
        self._tracker.resolve("docker:daemon", lambda d: Event("docker", "info", "resolved", "✅ Docker снова доступен",
                                                               f"Недоступен был {fmt_duration(d)}", data={"notify": True}))

        tracked = [c for c in containers if self._tracked(c)]
        names = {c.name for c in tracked}
        explicit = set(self.cfg.watch)

        if self._known is not None:
            for name in sorted(names - self._known):
                self._bus.emit(Event("docker", "info", "container_created", f"Новый контейнер: {name}"))
            for name in sorted(self._known - names):
                self._bus.emit(Event("docker", "info", "container_removed", f"Контейнер удалён: {name}"))
                self._expected.discard(name)
                for suffix in ("down", "unhealthy"):
                    self._tracker.resolve(f"docker:{name}:{suffix}")
        self._known = names

        for c in tracked:
            if c.state == "running":
                self._expected.add(c.name)
            expected = c.name in self._expected or c.name in explicit
            down = expected and c.state not in ("running",)
            sev = "warning" if c.state in ("restarting", "paused") else "critical"
            title = "Контейнер перезапускается" if c.state == "restarting" else "Контейнер остановлен"
            self._tracker.check(
                f"docker:{c.name}:down", down,
                lambda c=c, sev=sev, title=title: Event(
                    "docker", sev, "container_down", f"{title}: {c.name}",
                    f"Состояние: <b>{esc(c.state)}</b>\n{esc(c.status)}\nОбраз: <code>{esc(c.image)}</code>",
                    data={"container": c.name, "state": c.state}, buttons=self._buttons(c.name, c.state)),
                lambda d, c=c: Event("docker", "info", "resolved", f"✅ Контейнер снова работает: {c.name}",
                                     f"Простой: {fmt_duration(d)}", data={"notify": True}),
            )
            if self.cfg.alert_on_unhealthy:
                self._tracker.check(
                    f"docker:{c.name}:unhealthy", c.health == "unhealthy",
                    lambda c=c: Event("docker", "warning", "container_unhealthy", f"Контейнер unhealthy: {c.name}",
                                      esc(c.status), data={"container": c.name},
                                      buttons=self._buttons(c.name, c.state)),
                    lambda d, c=c: Event("docker", "info", "resolved", f"✅ Контейнер снова healthy: {c.name}",
                                         f"Длительность: {fmt_duration(d)}", data={"notify": True}),
                )
