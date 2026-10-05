"""Telegram bot: long polling, authorization, commands and inline buttons.

Only users listed in [telegram].admin_ids can interact with the bot. Everything the
bot can do is enumerated in this file; free-form text is never executed.
"""

from __future__ import annotations

import logging
import re
import threading
import time
from typing import TYPE_CHECKING, Any, Callable

from shelter_monitor.agent.actions import ActionError
from shelter_monitor.agent.bot import views
from shelter_monitor.agent.events import CATEGORIES, Event
from shelter_monitor.agent.notifier import keyboard
from shelter_monitor.telegram import TelegramAPI, TelegramError
from shelter_monitor.util import esc, fmt_ts

if TYPE_CHECKING:  # pragma: no cover
    from shelter_monitor.agent.app import Agent

log = logging.getLogger(__name__)

STALE_UPDATE_SECONDS = 120
MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")

BOT_COMMANDS = [
    ("status", "Сводка по серверу"),
    ("metrics", "CPU, память, диски, сеть"),
    ("docker", "Контейнеры Docker"),
    ("services", "Сервисы systemd"),
    ("ssh", "SSH-входы и попытки"),
    ("events", "Последние события"),
    ("devices", "Устройства в LAN"),
    ("check", "Проверить всё сейчас"),
    ("notify", "Настройки уведомлений"),
    ("mute", "Выключить уведомления: /mute 2h"),
    ("unmute", "Включить уведомления"),
    ("actions", "Перезапуск сервисов/контейнеров"),
    ("help", "Справка"),
]


def parse_duration(text: str, default_minutes: int = 60) -> int | None:
    """'30m', '2h', '1d', '45' (minutes) -> seconds. None if invalid."""
    text = text.strip().lower()
    if not text:
        return default_minutes * 60
    m = re.fullmatch(r"(\d{1,4})\s*([mhdмчд]?)", text)
    if not m:
        return None
    value = int(m.group(1))
    unit = m.group(2) or "m"
    mult = {"m": 60, "м": 60, "h": 3600, "ч": 3600, "d": 86400, "д": 86400}[unit]
    seconds = value * mult
    return seconds if 0 < seconds <= 30 * 86400 else None


class Bot:
    def __init__(self, agent: "Agent", api: TelegramAPI, admin_ids: list[int]):
        self.agent = agent
        self.api = api
        self.admins = set(admin_ids)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._poll_loop, name="tg-bot", daemon=True)
        self._offset: int | None = None
        self.async_work = True  # slow work (checks, actions) runs off the polling thread
        self._unauthorized_seen: dict[int, float] = {}
        self._views: dict[str, Callable[[], views.View]] = {
            "status": lambda: views.status_view(agent),
            "metrics": lambda: views.metrics_view(agent),
            "docker": lambda: views.docker_view(agent),
            "services": lambda: views.services_view(agent),
            "ssh": lambda: views.ssh_view(agent),
            "events": lambda: views.events_view(agent),
            "events_all": lambda: views.events_view(agent, show_all=True),
            "devices": lambda: views.devices_view(agent),
            "notify": lambda: views.notify_view(agent),
            "actions": lambda: views.actions_view(agent),
        }

    # -- lifecycle -----------------------------------------------------------------

    def start(self) -> None:
        try:
            self.api.set_my_commands(BOT_COMMANDS)
        except TelegramError as exc:
            log.warning("setMyCommands failed: %s", exc)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def is_alive(self) -> bool:
        return self._thread.is_alive()

    def _poll_loop(self) -> None:
        backoff = 1.0
        while not self._stop.is_set():
            try:
                updates = self.api.get_updates(self._offset, timeout=50)
                backoff = 1.0
            except TelegramError as exc:
                if exc.code == 409:
                    log.error("another process is polling this bot token (HTTP 409); retrying in 30s")
                    self._stop.wait(30)
                elif exc.code == 401:
                    log.error("Telegram rejected the bot token (401); retrying in 5 min")
                    self._stop.wait(300)
                else:
                    log.warning("getUpdates failed: %s (retry in %.0fs)", exc, backoff)
                    self._stop.wait(backoff)
                    backoff = min(backoff * 2, 60)
                continue
            for update in updates:
                self._offset = update["update_id"] + 1
                try:
                    self.handle_update(update)
                except Exception:
                    log.exception("failed to handle update")

    def _spawn(self, fn: Callable[[], None]) -> None:
        if not self.async_work:
            fn()
            return

        def run() -> None:
            try:
                fn()
            except Exception:
                log.exception("background bot job failed")

        threading.Thread(target=run, name="tg-job", daemon=True).start()

    # -- dispatch ------------------------------------------------------------------

    def is_admin(self, user: dict[str, Any] | None) -> bool:
        return bool(user) and user.get("id") in self.admins  # type: ignore[union-attr]

    def handle_update(self, update: dict[str, Any]) -> None:
        if "message" in update:
            msg = update["message"]
            if time.time() - msg.get("date", 0) > STALE_UPDATE_SECONDS:
                return  # queued while the agent was offline
            self.handle_message(msg)
        elif "callback_query" in update:
            self.handle_callback(update["callback_query"])

    def _deny(self, user: dict[str, Any] | None, chat_id: int | None) -> None:
        uid = (user or {}).get("id", 0)
        now = time.time()
        if now - self._unauthorized_seen.get(uid, 0) < 600:
            return
        self._unauthorized_seen[uid] = now
        log.warning("unauthorized Telegram access from user %s (@%s)", uid, (user or {}).get("username", ""))
        self.agent.bus.emit(Event(
            "security", "info", "telegram_unauthorized", "Попытка доступа к боту от неизвестного пользователя",
            f"ID: <code>{uid}</code> @{esc((user or {}).get('username', '—'))}", data={"user_id": uid}))
        if chat_id is not None:
            self._send(chat_id, f"⛔ Доступ запрещён.\nВаш Telegram ID: <code>{uid}</code>")

    def _send(self, chat_id: int, text: str, rows: views.Rows | None = None) -> None:
        try:
            self.api.send_message(chat_id, text[:4096], keyboard(rows or []))
        except TelegramError as exc:
            log.warning("sendMessage failed: %s", exc)

    def _edit(self, chat_id: int, message_id: int, text: str, rows: views.Rows | None = None) -> None:
        try:
            self.api.edit_message_text(chat_id, message_id, text[:4096], keyboard(rows or []))
        except TelegramError as exc:
            if "not modified" not in str(exc):
                log.warning("editMessageText failed: %s", exc)
                self._send(chat_id, text, rows)

    def _render(self, name: str) -> views.View:
        try:
            return self._views[name]()
        except Exception as exc:
            log.exception("view %s failed", name)
            return f"❌ Ошибка при получении данных: {esc(exc)}", [views.BACK]

    def handle_message(self, msg: dict[str, Any]) -> None:
        chat_id = msg["chat"]["id"]
        user = msg.get("from")
        text = (msg.get("text") or "").strip()
        if not text.startswith("/"):
            if self.is_admin(user) and msg["chat"].get("type") == "private":
                self._send(chat_id, "Я понимаю только команды. /help — список команд.")
            elif not self.is_admin(user) and msg["chat"].get("type") == "private":
                self._deny(user, chat_id)
            return
        command, _, arg = text.partition(" ")
        command = command[1:].split("@", 1)[0].lower()
        if command == "id":  # harmless, helps with initial configuration
            self._send(chat_id, f"Ваш ID: <code>{(user or {}).get('id')}</code>\nID чата: <code>{chat_id}</code>")
            return
        if not self.is_admin(user):
            self._deny(user, chat_id)
            return

        if command in ("start", "menu", "status"):
            self._send(chat_id, *self._render("status"))
        elif command == "help":
            self._send(chat_id, views.HELP_TEXT + "\n\n" + views.about_text(self.agent), views.MAIN_MENU)
        elif command in ("metrics", "docker", "services", "ssh", "events", "devices", "notify", "actions"):
            self._send(chat_id, *self._render(command))
        elif command == "restart":
            self._send(chat_id, *self._render("actions"))
        elif command == "check":
            self._send(chat_id, "⏳ Выполняю проверки…")

            def job() -> None:
                self.agent.run_checks()
                self._send(chat_id, *self._render("status"))
            self._spawn(job)
        elif command == "mute":
            seconds = parse_duration(arg)
            if seconds is None:
                self._send(chat_id, "Формат: /mute 30m, /mute 2h, /mute 1d (максимум 30 дней)")
                return
            until = self.agent.settings.mute(seconds)
            self._send(chat_id, f"🔕 Уведомления выключены до {fmt_ts(until)}", [[("🔔 Включить", "unmute")]])
        elif command == "unmute":
            self.agent.settings.unmute()
            self._send(chat_id, "🔔 Уведомления включены")
        else:
            self._send(chat_id, "Неизвестная команда. /help — список команд.")

    def handle_callback(self, cq: dict[str, Any]) -> None:
        user = cq.get("from")
        data = cq.get("data") or ""
        message = cq.get("message") or {}
        chat_id = (message.get("chat") or {}).get("id")
        message_id = message.get("message_id")
        if not self.is_admin(user):
            self._answer(cq["id"], "⛔ Доступ запрещён", alert=True)
            self._deny(user, None)
            return
        uid = user["id"]  # type: ignore[index]
        note = ""

        if data.startswith("v:"):
            name = data[2:]
            if name in self._views and chat_id is not None:
                self._edit(chat_id, message_id, *self._render(name))
        elif data == "chk":
            self._answer(cq["id"], "Выполняю проверки…")

            def job() -> None:
                self.agent.run_checks()
                if chat_id is not None:
                    self._edit(chat_id, message_id, *self._render("status"))
            self._spawn(job)
            return
        elif data.startswith("mute:"):
            minutes = data[5:]
            if minutes.isdigit() and 0 < int(minutes) <= 43200:
                until = self.agent.settings.mute(int(minutes) * 60)
                note = f"Выключены до {fmt_ts(until)}"
            if chat_id is not None:
                self._edit(chat_id, message_id, *self._render("notify"))
        elif data == "unmute":
            self.agent.settings.unmute()
            note = "Уведомления включены"
            if chat_id is not None:
                self._edit(chat_id, message_id, *self._render("notify"))
        elif data.startswith("cat:"):
            cat = data[4:]
            if cat in CATEGORIES:
                enabled = self.agent.settings.toggle_category(cat)
                note = f"{CATEGORIES[cat]}: {'включено' if enabled else 'выключено'}"
                if chat_id is not None:
                    self._edit(chat_id, message_id, *self._render("notify"))
        elif data.startswith("dev:trust:") or data.startswith("dev:untrust:"):
            mac = data.split(":", 2)[2]
            if MAC_RE.match(mac):
                trusted = data.startswith("dev:trust:")
                ok = self.agent.storage.set_device_trusted(mac, trusted)
                note = ("Устройство отмечено как доверенное" if trusted else "Доверие снято") if ok else "Устройство не найдено"
                if ok and chat_id is not None and message.get("text", "").startswith("📡"):
                    self._edit(chat_id, message_id, *self._render("devices"))
        elif data == "lan:scan":
            if self.agent.trigger_task("lan"):
                note = "Сканирование запущено, обновите список через несколько секунд"
            else:
                note = "Обнаружение устройств выключено"
        elif data.startswith("act:"):
            self._request_action(cq, data, uid, chat_id)
            return
        elif data.startswith("cf:") or data.startswith("cx:"):
            self._confirm_action(cq, data, uid, chat_id, message_id)
            return
        self._answer(cq["id"], note)

    def _answer(self, callback_id: str, text: str = "", alert: bool = False) -> None:
        try:
            self.api.answer_callback_query(callback_id, text[:190], alert)
        except TelegramError as exc:
            log.debug("answerCallbackQuery failed: %s", exc)

    # -- actions -------------------------------------------------------------------

    def _request_action(self, cq: dict[str, Any], data: str, uid: int, chat_id: int | None) -> None:
        parts = data.split(":")
        if len(parts) != 3 or parts[1] not in ("s", "c") or not parts[2].isdigit() or chat_id is None:
            self._answer(cq["id"], "Некорректный запрос")
            return
        kind = "service" if parts[1] == "s" else "container"
        try:
            target = self.agent.actions.target_by_index(kind, int(parts[2]))
            action = self.agent.actions.request(kind, target, uid)
        except ActionError as exc:
            self._answer(cq["id"], str(exc), alert=True)
            return
        self._answer(cq["id"])
        self._send(
            chat_id,
            f"⚠️ <b>Подтвердите действие</b>\n\n{esc(action.label)}\nна сервере <code>{esc(self.agent.host)}</code>\n\n"
            f"Запрос действует {self.agent.cfg.actions.confirm_timeout} с.",
            [[("✅ Подтвердить", f"cf:{action.token}"), ("✖️ Отмена", f"cx:{action.token}")]],
        )

    def _confirm_action(self, cq: dict[str, Any], data: str, uid: int, chat_id: int | None, message_id: int | None) -> None:
        token = data[3:]
        if data.startswith("cx:"):
            action = self.agent.actions.cancel(token, uid)
            self._answer(cq["id"], "Отменено" if action else "Запрос не найден")
            if chat_id is not None and message_id is not None:
                self._edit(chat_id, message_id, "✖️ Действие отменено" + (f": {esc(action.label)}" if action else ""))
            return
        self._answer(cq["id"], "Выполняю…")
        if chat_id is not None and message_id is not None:
            self._edit(chat_id, message_id, "⏳ Выполняется…")

        def job() -> None:
            try:
                action, result = self.agent.actions.confirm(token, uid)
                text = f"{'✅' if result.startswith('Готово') else '❌'} {esc(action.label)}\n{esc(result)}"
            except ActionError as exc:
                text = f"❌ {esc(exc)}"
            if chat_id is not None and message_id is not None:
                self._edit(chat_id, message_id, text)
        self._spawn(job)
