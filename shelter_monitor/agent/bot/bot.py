"""Telegram bot: long polling, authorization, commands and inline buttons.

Only users listed in [telegram].admin_ids can interact with the bot. Everything the
bot can do is enumerated in this file; free-form text is never executed.

UX rules:
  * every button press is answered (toast) and visibly changes something;
  * buttons under notifications never overwrite the notification with a menu -
    they open a new message (o:...) or update the notification itself (device trust);
  * one-shot buttons (confirmations, device decisions) are replaced by the outcome,
    so stale buttons do not linger.
"""

from __future__ import annotations

import html
import logging
import re
import threading
import time
from typing import TYPE_CHECKING, Any, Callable

from shelter_monitor.agent.actions import OPS, ActionError
from shelter_monitor.agent.bot import views
from shelter_monitor.agent.events import CATEGORIES, Event
from shelter_monitor.agent.lan import describe_device, device_buttons
from shelter_monitor.agent.notifier import keyboard
from shelter_monitor.telegram import TelegramAPI, TelegramError
from shelter_monitor.util import esc, fmt_ts

if TYPE_CHECKING:  # pragma: no cover
    from shelter_monitor.agent.app import Agent

log = logging.getLogger(__name__)

STALE_UPDATE_SECONDS = 120
MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
CONTAINER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,127}$")
UNIT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9@_.\-]{0,127}$")

BOT_COMMANDS = [
    ("status", "Сводка по серверу"),
    ("metrics", "CPU, память, диски, сеть"),
    ("docker", "Контейнеры: логи, перезапуск"),
    ("services", "Сервисы systemd"),
    ("security", "Кто стучался: SSH, файрвол, подключения"),
    ("ssh", "SSH-входы и попытки"),
    ("devices", "Устройства в LAN"),
    ("events", "Последние события"),
    ("check", "Проверить всё прямо сейчас"),
    ("diag", "Диагностика настройки агента"),
    ("actions", "Разрешённые действия"),
    ("notify", "Настройки уведомлений"),
    ("mute", "Выключить уведомления: /mute 2h"),
    ("unmute", "Включить уведомления"),
    ("help", "Справка"),
]

# commands that simply show a view
VIEW_COMMANDS = {
    "start": "status", "menu": "status", "status": "status", "metrics": "metrics", "docker": "docker",
    "containers": "docker", "services": "services", "ssh": "ssh", "security": "security", "events": "events",
    "devices": "devices", "notify": "notify", "actions": "actions", "restart": "actions", "diag": "diag",
}


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


def user_label(user: dict[str, Any] | None) -> str:
    user = user or {}
    if user.get("username"):
        return "@" + str(user["username"])
    return str(user.get("first_name") or user.get("id", "?"))


class Bot:
    def __init__(self, agent: "Agent", api: TelegramAPI, admin_ids: list[int]):
        self.agent = agent
        self.api = api
        self.admins = set(admin_ids)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._poll_loop, name="tg-bot", daemon=True)
        self._offset: int | None = None
        self._unauthorized_seen: dict[int, float] = {}
        self.async_work = True  # slow work (checks, actions, scans) runs off the polling thread
        self._views: dict[str, Callable[[str], views.View]] = {
            "status": lambda arg: views.status_view(agent),
            "metrics": lambda arg: views.metrics_view(agent),
            "docker": lambda arg: views.docker_view(agent, int(arg) if arg.isdigit() else 0),
            "services": lambda arg: views.services_view(agent),
            "ssh": lambda arg: views.ssh_view(agent),
            "security": lambda arg: views.security_view(agent),
            "events": lambda arg: views.events_view(agent),
            "events_all": lambda arg: views.events_view(agent, show_all=True),
            "devices": lambda arg: views.devices_view(agent),
            "notify": lambda arg: views.notify_view(agent),
            "actions": lambda arg: views.actions_view(agent),
            "diag": lambda arg: views.diag_view(agent),
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

    # -- telegram helpers ------------------------------------------------------------

    def is_admin(self, user: dict[str, Any] | None) -> bool:
        return bool(user) and user.get("id") in self.admins  # type: ignore[union-attr]

    def _send(self, chat_id: int, text: str, rows: views.Rows | None = None) -> int | None:
        try:
            result = self.api.send_message(chat_id, text[:4096], keyboard(rows or []))
            return (result or {}).get("message_id")
        except TelegramError as exc:
            log.warning("sendMessage failed: %s", exc)
            return None

    def _edit(self, chat_id: int | None, message_id: int | None, text: str, rows: views.Rows | None = None) -> None:
        if chat_id is None:
            return
        if message_id is None:
            self._send(chat_id, text, rows)
            return
        try:
            self.api.edit_message_text(chat_id, message_id, text[:4096], keyboard(rows or []))
        except TelegramError as exc:
            if "not modified" in str(exc):
                return
            log.warning("editMessageText failed: %s", exc)
            self._send(chat_id, text, rows)  # message too old / deleted: send a fresh one

    def _answer(self, callback_id: str, text: str = "", alert: bool = False) -> None:
        try:
            self.api.answer_callback_query(callback_id, text[:190], alert)
        except TelegramError as exc:
            log.debug("answerCallbackQuery failed: %s", exc)

    def _render(self, name: str, arg: str = "") -> views.View:
        try:
            return self._views[name](arg)
        except Exception as exc:
            log.exception("view %s failed", name)
            return f"❌ Ошибка при получении данных: {esc(exc)}", [views.BACK]

    def _safe(self, fn: Callable[[], views.View]) -> views.View:
        try:
            return fn()
        except Exception as exc:
            log.exception("view failed")
            return f"❌ Ошибка при получении данных: {esc(exc)}", [views.BACK]

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

    # -- dispatch ------------------------------------------------------------------

    def handle_update(self, update: dict[str, Any]) -> None:
        if "message" in update:
            msg = update["message"]
            if time.time() - msg.get("date", 0) > STALE_UPDATE_SECONDS:
                return  # queued while the agent was offline
            self.handle_message(msg)
        elif "callback_query" in update:
            self.handle_callback(update["callback_query"])

    def handle_message(self, msg: dict[str, Any]) -> None:
        chat_id = msg["chat"]["id"]
        user = msg.get("from")
        text = (msg.get("text") or "").strip()
        private = msg["chat"].get("type") == "private"
        if not text.startswith("/"):
            if self.is_admin(user) and private:
                self._send(chat_id, "Я понимаю только команды и кнопки. /help — список команд.", views.MAIN_MENU)
            elif not self.is_admin(user) and private:
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

        if command in VIEW_COMMANDS:
            self._send(chat_id, *self._render(VIEW_COMMANDS[command]))
        elif command == "help":
            self._send(chat_id, views.HELP_TEXT + "\n\n" + views.about_text(self.agent), views.MAIN_MENU)
        elif command == "check":
            message_id = self._send(chat_id, "⏳ Выполняю все проверки…")

            def job() -> None:
                result = self.agent.run_checks()
                self._edit(chat_id, message_id, *self._safe(lambda: views.check_result_view(self.agent, result)))
            self._spawn(job)
        elif command == "mute":
            seconds = parse_duration(arg)
            if seconds is None:
                self._send(chat_id, "Формат: /mute 30m, /mute 2h, /mute 1d (максимум 30 дней)")
                return
            until = self.agent.settings.mute(seconds)
            self._send(chat_id, f"🔕 Уведомления выключены до {fmt_ts(until)}", [[("🔔 Включить сейчас", "unmute:msg")]])
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
        ctx = CallbackContext(self, cq, user or {}, chat_id, message_id)
        try:
            note = self._route(ctx, data)
        except Exception:
            log.exception("callback %r failed", data)
            note = "❌ Ошибка, подробности в логе агента"
        if not ctx.answered:
            self._answer(cq["id"], note or "")

    def _route(self, ctx: "CallbackContext", data: str) -> str:
        prefix, _, rest = data.partition(":")
        if prefix == "v":
            name, _, arg = rest.partition(":")
            if name not in self._views:
                return "Экран устарел, откройте /status"
            ctx.edit(*self._render(name, arg))
            return "Обновлено" if name != "status" else ""
        if prefix == "o":
            if rest not in self._views:
                return "Экран устарел, откройте /status"
            ctx.send(*self._render(rest))
            return ""
        if data == "chk":
            return self._run_checks(ctx)
        if prefix == "mute":
            if rest.isdigit() and 0 < int(rest) <= 43200:
                until = self.agent.settings.mute(int(rest) * 60)
                ctx.edit(*self._render("notify"))
                return f"Уведомления выключены до {fmt_ts(until)}"
            return "Некорректная длительность"
        if prefix == "unmute":
            self.agent.settings.unmute()
            if rest == "msg":  # button under the /mute reply: update that message
                ctx.edit("🔔 Уведомления снова включены")
            else:
                ctx.edit(*self._render("notify"))
            return "Уведомления включены"
        if prefix == "cat":
            if rest not in CATEGORIES:
                return "Неизвестная категория"
            enabled = self.agent.settings.toggle_category(rest)
            ctx.edit(*self._render("notify"))
            return f"{CATEGORIES[rest]}: {'включено' if enabled else 'выключено'}"
        if prefix in ("dev", "devv"):
            return self._device(ctx, prefix == "devv", rest)
        if data == "lan:scan":
            return self._lan_scan(ctx)
        if prefix == "c":
            if not CONTAINER_RE.match(rest):
                return "Некорректное имя контейнера"
            ctx.edit(*self._safe(lambda: views.container_view(self.agent, rest)))
            return ""
        if prefix == "cl":
            if not CONTAINER_RE.match(rest):
                return "Некорректное имя контейнера"
            view = self._safe(lambda: views.container_logs_view(self.agent, rest))
            if ctx.message_text.startswith("📋 Логи"):
                ctx.edit(*view)  # refresh in place
            else:
                ctx.send(*view)
            return ""
        if prefix == "a":
            return self._request_action(ctx, rest)
        if prefix in ("cf", "cx"):
            return self._confirm_action(ctx, prefix == "cf", rest)
        return "Кнопка устарела"

    # -- checks / scans ----------------------------------------------------------------

    def _run_checks(self, ctx: "CallbackContext") -> str:
        ctx.answer("Выполняю все проверки, это займёт несколько секунд…")
        ctx.edit("⏳ Выполняю все проверки…")

        def job() -> None:
            result = self.agent.run_checks()
            ctx.edit(*self._safe(lambda: views.check_result_view(self.agent, result)))
        self._spawn(job)
        return ""

    def _lan_scan(self, ctx: "CallbackContext") -> str:
        if self.agent.lan is None:
            return "Обнаружение устройств выключено"
        ctx.answer("Сканирую сеть…")
        if ctx.message_text.startswith("📡"):
            ctx.edit("📡 ⏳ Сканирую локальную сеть…")

        def job() -> None:
            self.agent.run_task("lan")
            view = self._render("devices")
            if ctx.message_text.startswith("📡"):
                ctx.edit(*view)
            else:
                ctx.send(*view)
        self._spawn(job)
        return ""

    # -- devices ---------------------------------------------------------------------

    def _device(self, ctx: "CallbackContext", in_list: bool, rest: str) -> str:
        op, _, mac = rest.partition(":")
        storage = self.agent.storage
        if op == "trustall":
            count = storage.trust_all_devices()
            ctx.edit(*self._render("devices"))
            return f"Доверенными отмечено: {count}"
        if op == "forgetall":
            if mac != "yes":
                ctx.edit("🗑 <b>Забыть все устройства?</b>\nСписок очистится, а при следующем сканировании все найденные "
                         "устройства будут записаны как известные (без уведомлений).",
                         [[("Да, забыть все", "devv:forgetall:yes"), ("Отмена", "v:devices")]])
                return ""
            count = storage.forget_devices()
            ctx.edit(*self._render("devices"))
            return f"Удалено устройств: {count}"
        if op not in ("trust", "untrust", "forget") or not MAC_RE.match(mac):
            return "Кнопка устарела"
        device = storage.get_device(mac)
        if device is None:
            if not in_list:
                ctx.edit(ctx.message_html() + "\n\n<i>Устройство уже удалено из списка.</i>",
                         [[("📋 Все устройства", "o:devices")]])
            return "Устройство не найдено"
        who = f"{esc(user_label(ctx.user))} · {fmt_ts(time.time())}"
        if op == "forget":
            storage.delete_device(mac)
            note = "Устройство удалено из списка"
            if not in_list:
                ctx.edit(f"🗑 <b>Устройство забыто</b>\n\n{describe_device(device.ip, mac, device.hostname, device.iface)}"
                         f"\n\nЕсли оно снова появится в сети, придёт новое уведомление.\n<i>{who}</i>",
                         [[("📋 Все устройства", "o:devices")]])
        else:
            trusted = op == "trust"
            storage.set_device_trusted(mac, trusted)
            note = "Отмечено как доверенное" if trusted else "Доверие снято"
            if not in_list:
                head = "✅ <b>Доверенное устройство</b>" if trusted else "❓ <b>Устройство не доверенное</b>"
                ctx.edit(f"{head}\n\n{describe_device(device.ip, mac, device.hostname, device.iface)}\n\n<i>{who}</i>",
                         device_buttons(mac, trusted))
        if in_list:
            ctx.edit(*self._render("devices"))
        return note

    # -- actions -----------------------------------------------------------------------

    def _request_action(self, ctx: "CallbackContext", rest: str) -> str:
        op, _, target = rest.partition(":")
        if op not in OPS or ctx.chat_id is None:
            return "Кнопка устарела"
        needs_target = OPS[op][1]
        if needs_target and not (UNIT_RE.match(target) if op == "sr" else CONTAINER_RE.match(target)):
            return "Некорректный объект"
        if not needs_target:
            target = ""
        try:
            action = self.agent.actions.request(op, target, ctx.user_id)
        except ActionError as exc:
            ctx.answer(str(exc), alert=True)
            return ""
        warning = self.agent.actions.warning(action)
        text = (f"⚠️ <b>Подтвердите действие</b>\n\n{esc(action.label)}\nна сервере <code>{esc(self.agent.host)}</code>"
                + (f"\n\n{esc(warning)}" if warning else "")
                + f"\n\nЗапрос действует {self.agent.cfg.actions.confirm_timeout} с.")
        message_id = ctx.send(text, [[("✅ Подтвердить", f"cf:{action.token}"), ("✖️ Отмена", f"cx:{action.token}")]])
        if message_id is not None:
            self._expire_later(ctx.chat_id, message_id, action.token, action.label)
        return ""

    def _expire_later(self, chat_id: int, message_id: int, token: str, label: str) -> None:
        """Remove the confirmation buttons once the request has expired."""
        def expire() -> None:
            if self.agent.actions.cancel_expired(token):
                self._edit(chat_id, message_id, f"⌛ Время на подтверждение истекло: {esc(label)}")
        timer = threading.Timer(self.agent.cfg.actions.confirm_timeout + 1, expire)
        timer.daemon = True
        timer.start()

    def _confirm_action(self, ctx: "CallbackContext", confirm: bool, token: str) -> str:
        if not confirm:
            action = self.agent.actions.cancel(token, ctx.user_id)
            ctx.edit("✖️ Действие отменено" + (f": {esc(action.label)}" if action else ""))
            return "Отменено"
        ctx.answer("Выполняю…")
        ctx.edit("⏳ Выполняется…")

        def job() -> None:
            try:
                action, ok, output = self.agent.actions.confirm(token, ctx.user_id)
            except ActionError as exc:
                ctx.edit(f"❌ {esc(exc)}")
                return
            text = f"{'✅' if ok else '❌'} <b>{esc(action.label)}</b>"
            if output:
                text += f"\n<pre>{esc(output[-1500:])}</pre>"
            text += f"\n<i>{esc(user_label(ctx.user))} · {fmt_ts(time.time())}</i>"
            rows: views.Rows = []
            if action.op in ("cr", "cs", "ct"):
                rows = [[("🐳 Открыть контейнер", f"c:{action.target}")]] if len(action.target) < 60 else []
            elif action.op == "sr":
                rows = [[("⚙️ Сервисы", "o:services")]]
            ctx.edit(text, rows)
        self._spawn(job)
        return ""


class CallbackContext:
    """Per-button-press helpers: answer once, edit the pressed message, send new ones."""

    def __init__(self, bot: Bot, cq: dict[str, Any], user: dict[str, Any], chat_id: int | None, message_id: int | None):
        self.bot = bot
        self.cq = cq
        self.user = user
        self.user_id = int(user.get("id", 0))
        self.chat_id = chat_id
        self.message_id = message_id
        self.answered = False
        message = cq.get("message") or {}
        self.message_text = message.get("text") or ""
        self._entities = message.get("entities") or []

    def answer(self, text: str = "", alert: bool = False) -> None:
        if not self.answered:
            self.answered = True
            self.bot._answer(self.cq["id"], text, alert)

    def edit(self, text: str, rows: views.Rows | None = None) -> None:
        self.bot._edit(self.chat_id, self.message_id, text, rows)

    def send(self, text: str, rows: views.Rows | None = None) -> int | None:
        if self.chat_id is None:
            return None
        return self.bot._send(self.chat_id, text, rows)

    def message_html(self) -> str:
        """The pressed message as HTML (bold/code entities restored), for edits that keep it."""
        return entities_to_html(self.message_text, self._entities)


def entities_to_html(text: str, entities: list[dict[str, Any]]) -> str:
    """Rebuild Telegram HTML from text + entities (offsets are in UTF-16 code units)."""
    tags = {"bold": ("<b>", "</b>"), "italic": ("<i>", "</i>"), "code": ("<code>", "</code>"),
            "pre": ("<pre>", "</pre>"), "underline": ("<u>", "</u>"), "strikethrough": ("<s>", "</s>")}
    units = text.encode("utf-16-le")
    opens: dict[int, list[str]] = {}
    closes: dict[int, list[str]] = {}
    for ent in entities:
        if ent.get("type") not in tags:
            continue
        start, end = ent["offset"], ent["offset"] + ent["length"]
        opens.setdefault(start, []).append(tags[ent["type"]][0])
        closes.setdefault(end, []).insert(0, tags[ent["type"]][1])
    out = []
    n = len(units) // 2
    i = 0
    while i <= n:
        out.extend(closes.get(i, []))
        out.extend(opens.get(i, []))
        if i == n:
            break
        # copy one UTF-16 unit, or a surrogate pair at once
        unit = int.from_bytes(units[2 * i:2 * i + 2], "little")
        width = 2 if 0xD800 <= unit <= 0xDBFF else 1
        out.append(html.escape(units[2 * i:2 * (i + width)].decode("utf-16-le"), quote=False))
        i += width
    return "".join(out)
