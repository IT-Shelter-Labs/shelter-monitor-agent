"""Decides which events become Telegram notifications and formats them."""

from __future__ import annotations

import json
import logging
import threading
import time
from typing import Any

from shelter_monitor.agent.events import CATEGORIES, SEVERITY_RANK, Event
from shelter_monitor.util import esc, fmt_ts

log = logging.getLogger(__name__)

SEVERITY_ICON = {"info": "ℹ️", "warning": "⚠️", "critical": "🚨"}
KIND_ICON = {"ssh_login": "🔑", "resolved": "", "internet_restored": ""}


def keyboard(rows: list[list[tuple[str, str]]]) -> dict[str, Any] | None:
    if not rows:
        return None
    return {"inline_keyboard": [[{"text": t, "callback_data": d} for t, d in row] for row in rows]}


def format_event(event: Event, host: str) -> str:
    icon = KIND_ICON.get(event.kind, SEVERITY_ICON.get(event.severity, ""))
    text = f"{icon + ' ' if icon else ''}<b>{esc(event.title)}</b>\n🖥 <code>{esc(host)}</code> · {fmt_ts(event.ts)}"
    if event.body:
        text += "\n\n" + event.body  # body is already HTML-escaped by the producer
    return text


class NotificationSettings:
    """Runtime notification settings that can be changed from Telegram; persisted in the kv table."""

    def __init__(self, storage: Any):
        self._storage = storage
        self._lock = threading.Lock()

    @property
    def mute_until(self) -> float:
        return float(self._storage.kv_get("notify.mute_until", "0") or 0)

    def mute(self, seconds: float) -> float:
        until = time.time() + seconds
        self._storage.kv_set("notify.mute_until", str(until))
        return until

    def unmute(self) -> None:
        self._storage.kv_set("notify.mute_until", "0")

    def is_muted(self, now: float | None = None) -> bool:
        return self.mute_until > (now or time.time())

    @property
    def disabled_categories(self) -> set[str]:
        raw = self._storage.kv_get("notify.disabled_categories", "[]") or "[]"
        try:
            return {c for c in json.loads(raw) if c in CATEGORIES}
        except ValueError:
            return set()

    def toggle_category(self, category: str) -> bool:
        """Toggle a category, return True if it is enabled afterwards."""
        if category not in CATEGORIES:
            raise ValueError(category)
        with self._lock:
            disabled = self.disabled_categories
            if category in disabled:
                disabled.discard(category)
            else:
                disabled.add(category)
            self._storage.kv_set("notify.disabled_categories", json.dumps(sorted(disabled)))
        return category not in disabled


class Notifier:
    def __init__(self, outbox: Any, chats: list[int], host: str, settings: NotificationSettings,
                 min_severity: str = "warning", mute_allows_critical: bool = True, silent_info: bool = True):
        self._outbox = outbox
        self._chats = chats
        self._host = host
        self.settings = settings
        self._min_rank = SEVERITY_RANK[min_severity]
        self._mute_allows_critical = mute_allows_critical
        self._silent_info = silent_info

    def should_notify(self, event: Event) -> bool:
        if event.data.get("notify") is False:
            return False
        forced = event.data.get("notify") is True
        if not forced and SEVERITY_RANK[event.severity] < self._min_rank:
            return False
        if event.category in self.settings.disabled_categories and event.severity != "critical":
            return False
        if self.settings.is_muted():
            return event.severity == "critical" and self._mute_allows_critical
        return True

    def handle(self, event: Event) -> None:
        if not self.should_notify(event):
            return
        text = format_event(event, self._host)
        silent = event.data.get("silent", self._silent_info and event.severity == "info")
        for chat in self._chats:
            self._outbox.send(chat, text, keyboard(event.buttons), silent=silent)

    def broadcast(self, text: str, silent: bool = False) -> None:
        for chat in self._chats:
            self._outbox.send(chat, text, silent=silent)
