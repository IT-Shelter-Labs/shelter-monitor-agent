"""Internet connectivity check via plain TCP connects (no ICMP / root needed)."""

from __future__ import annotations

import socket
import time

from shelter_monitor.agent.config import ConnectivitySection
from shelter_monitor.agent.events import AlertTracker, Event
from shelter_monitor.util import esc, fmt_duration


def tcp_check(target: str, timeout: float = 3.0) -> float | None:
    """Return connect latency in ms, or None on failure."""
    host, _, port = target.rpartition(":")
    host = host.strip("[]")
    start = time.monotonic()
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return (time.monotonic() - start) * 1000
    except OSError:
        return None


class ConnectivityMonitor:
    name = "connectivity"

    def __init__(self, cfg: ConnectivitySection, tracker: AlertTracker):
        self.cfg = cfg
        self.interval = cfg.interval
        self._tracker = tracker
        self._failures = 0
        self.last_results: dict[str, float | None] = {}

    def tick(self) -> None:
        results = {t: tcp_check(t) for t in self.cfg.targets}
        self.last_results = results
        all_failed = bool(results) and all(v is None for v in results.values())
        self._failures = self._failures + 1 if all_failed else 0
        self._tracker.check(
            "connectivity",
            self._failures >= self.cfg.failures_before_alert,
            lambda: Event("network", "critical", "internet_down", "Нет доступа в интернет",
                          "Недоступны: " + ", ".join(f"<code>{esc(t)}</code>" for t in results)),
            lambda d: Event("network", "info", "internet_restored", "✅ Доступ в интернет восстановлен",
                            f"Связи не было примерно {fmt_duration(d + self.cfg.interval * self.cfg.failures_before_alert)}",
                            data={"notify": True}),
        )
