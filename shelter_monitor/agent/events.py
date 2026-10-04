"""Event model, event bus and alert state tracking.

Every monitor reports what it observes as :class:`Event` objects through the
:class:`EventBus`. The bus persists events and hands them to the notifier. The
event dict form (``Event.to_dict``) is also the wire format a future central
Shelter Monitor Hub would receive.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Protocol

log = logging.getLogger(__name__)

SEVERITY_RANK = {"info": 0, "warning": 1, "critical": 2}

CATEGORIES = {
    "system": "Ресурсы системы",
    "services": "Сервисы systemd",
    "docker": "Docker",
    "ssh": "SSH-входы",
    "security": "Безопасность",
    "network": "Сеть и связь",
    "lan": "Устройства в LAN",
    "agent": "Агент и действия",
}


@dataclass
class Event:
    category: str
    severity: str
    kind: str
    title: str
    body: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    # Inline keyboard rows attached to the notification: [[(text, callback_data), ...], ...]
    buttons: list[list[tuple[str, str]]] = field(default_factory=list)
    ts: float = field(default_factory=time.time)
    id: int = 0

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_RANK:
            raise ValueError(f"bad severity {self.severity!r}")
        if self.category not in CATEGORIES:
            raise ValueError(f"bad category {self.category!r}")

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d.pop("buttons", None)
        return d


class EventSink(Protocol):
    def handle(self, event: Event) -> None: ...


class EventBus:
    def __init__(self, storage: Any, host: str):
        self._storage = storage
        self._host = host
        self._sinks: list[EventSink] = []

    def subscribe(self, sink: EventSink) -> None:
        self._sinks.append(sink)

    def emit(self, event: Event) -> Event:
        try:
            event.id = self._storage.add_event(
                event.ts, self._host, event.category, event.severity, event.kind, event.title, event.body, event.data
            )
        except Exception:
            log.exception("failed to store event %s", event.kind)
        log.info("event [%s/%s] %s", event.category, event.severity, event.title)
        for sink in self._sinks:
            try:
                sink.handle(event)
            except Exception:
                log.exception("event sink failed")
        return event


@dataclass
class ActiveAlert:
    key: str
    since: float
    title: str
    severity: str


class AlertTracker:
    """Turns level-based conditions ("disk is 93% full") into edge events.

    An event is emitted when a condition starts firing, when its severity escalates
    and when it resolves - never on every check, so notifications stay quiet.
    """

    def __init__(self, bus: EventBus):
        self._bus = bus
        self._lock = threading.Lock()
        self._active: dict[str, ActiveAlert] = {}

    def check(
        self,
        key: str,
        firing: bool,
        make_fire: Callable[[], Event],
        make_resolve: Callable[[float], Event | None] | None = None,
    ) -> None:
        with self._lock:
            current = self._active.get(key)
        if firing:
            event = make_fire()
            if current is None or SEVERITY_RANK[event.severity] > SEVERITY_RANK[current.severity]:
                since = current.since if current else time.time()
                with self._lock:
                    self._active[key] = ActiveAlert(key, since, event.title, event.severity)
                self._bus.emit(event)
            return
        if current is not None:
            self.resolve(key, make_resolve)

    def resolve(self, key: str, make_resolve: Callable[[float], Event | None] | None = None) -> None:
        """Clear an alert; emit the resolve event (if given) only when it was active."""
        with self._lock:
            current = self._active.pop(key, None)
        if current is not None and make_resolve is not None:
            resolved = make_resolve(time.time() - current.since)
            if resolved is not None:
                self._bus.emit(resolved)

    def is_active(self, key: str) -> bool:
        with self._lock:
            return key in self._active

    def active(self) -> list[ActiveAlert]:
        with self._lock:
            return sorted(self._active.values(), key=lambda a: a.since)
