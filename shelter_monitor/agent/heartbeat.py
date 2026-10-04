"""Heartbeat sender.

The agent periodically reports "I'm alive" to an external endpoint. If the server
goes down completely (power loss, kernel panic, network outage), the heartbeats stop
and the external side raises the alarm - something an agent running on the dead
server itself can never do.

Supported receivers:
  * Shelter Watchdog (`shelter-watchdog`, included in this repository) - POST JSON
  * any "push" monitor: Healthchecks.io, Uptime Kuma push monitors, Cronitor... - GET
"""

from __future__ import annotations

import json
import logging
import socket
import time
import urllib.error
import urllib.request
from typing import Any, Callable

from shelter_monitor import __version__
from shelter_monitor.agent.config import HeartbeatSection

log = logging.getLogger(__name__)


def build_payload(agent_id: str, seq: int, boot_id: str, summary: dict[str, Any], alerts: int) -> dict[str, Any]:
    return {
        "type": "heartbeat",
        "schema": 1,
        "agent_id": agent_id,
        "hostname": socket.gethostname(),
        "version": __version__,
        "ts": time.time(),
        "seq": seq,
        "boot_id": boot_id,
        "active_alerts": alerts,
        "metrics": summary,
    }


class HeartbeatSender:
    name = "heartbeat"

    def __init__(self, cfg: HeartbeatSection, agent_id: str, boot_id: str,
                 summary_fn: Callable[[], dict[str, Any]], alerts_fn: Callable[[], int]):
        self.cfg = cfg
        self.interval = cfg.interval
        self._agent_id = agent_id
        self._boot_id = boot_id
        self._summary_fn = summary_fn
        self._alerts_fn = alerts_fn
        self._seq = 0
        self.last_ok: float = 0.0
        self.last_error: str = ""
        self._failures = 0

    def tick(self) -> None:
        self._seq += 1
        headers = {"User-Agent": f"shelter-agent/{__version__}"}
        if self.cfg.token:
            headers["Authorization"] = f"Bearer {self.cfg.token}"
        if self.cfg.method == "GET":
            req = urllib.request.Request(self.cfg.url, headers=headers, method="GET")
        else:
            try:
                summary = self._summary_fn()
            except Exception:
                log.exception("heartbeat summary failed")
                summary = {}
            body = json.dumps(build_payload(self._agent_id, self._seq, self._boot_id, summary, self._alerts_fn()))
            headers["Content-Type"] = "application/json"
            req = urllib.request.Request(self.cfg.url, data=body.encode(), headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.cfg.timeout) as resp:
                resp.read(1024)
            self.last_ok = time.time()
            self.last_error = ""
            if self._failures:
                log.info("heartbeat delivered again after %d failures", self._failures)
            self._failures = 0
        except (urllib.error.URLError, OSError, ValueError) as exc:
            self._failures += 1
            self.last_error = str(getattr(exc, "reason", exc))
            level = logging.WARNING if self._failures in (1, 10) or self._failures % 60 == 0 else logging.DEBUG
            log.log(level, "heartbeat failed (%d in a row): %s", self._failures, self.last_error)
