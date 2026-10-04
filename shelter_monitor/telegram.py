"""Minimal Telegram Bot API client built on urllib (no third-party dependencies).

Only the handful of methods the agent needs are wrapped. Outgoing notifications go
through :class:`Outbox`, a background sender that respects Telegram rate limits and
retries transient failures, so that monitoring threads never block on the network.
"""

from __future__ import annotations

import json
import logging
import queue
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger(__name__)

MAX_MESSAGE_LEN = 4096


class TelegramError(Exception):
    def __init__(self, message: str, code: int | None = None, retry_after: float | None = None):
        super().__init__(message)
        self.code = code
        self.retry_after = retry_after


class TelegramAPI:
    def __init__(self, token: str, api_url: str = "https://api.telegram.org", proxy: str = ""):
        if not token:
            raise ValueError("Telegram bot token is empty")
        self._base = f"{api_url.rstrip('/')}/bot{token}/"
        handlers: list[Any] = []
        if proxy:
            handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        self._opener = urllib.request.build_opener(*handlers)

    def call(self, method: str, params: dict[str, Any] | None = None, timeout: float = 20) -> Any:
        data = json.dumps(params or {}).encode()
        req = urllib.request.Request(
            self._base + method, data=data, headers={"Content-Type": "application/json"}, method="POST"
        )
        try:
            with self._opener.open(req, timeout=timeout) as resp:
                payload = json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            try:
                payload = json.loads(exc.read().decode())
            except Exception:
                raise TelegramError(f"{method}: HTTP {exc.code}", code=exc.code) from None
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            # Never include the URL in errors: it contains the bot token.
            raise TelegramError(f"{method}: network error: {getattr(exc, 'reason', exc)}") from None
        if not payload.get("ok"):
            params_ = payload.get("parameters") or {}
            raise TelegramError(
                f"{method}: {payload.get('description', 'unknown error')}",
                code=payload.get("error_code"),
                retry_after=params_.get("retry_after"),
            )
        return payload.get("result")

    # -- convenience wrappers ---------------------------------------------------------

    def get_me(self) -> dict[str, Any]:
        return self.call("getMe")

    def get_updates(self, offset: int | None, timeout: int = 50) -> list[dict[str, Any]]:
        params: dict[str, Any] = {"timeout": timeout, "allowed_updates": ["message", "callback_query"]}
        if offset is not None:
            params["offset"] = offset
        return self.call("getUpdates", params, timeout=timeout + 15)

    def send_message(
        self, chat_id: int | str, text: str, reply_markup: dict[str, Any] | None = None, silent: bool = False
    ) -> dict[str, Any]:
        params: dict[str, Any] = {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
            "disable_notification": silent,
        }
        if reply_markup:
            params["reply_markup"] = reply_markup
        return self.call("sendMessage", params)

    def edit_message_text(
        self, chat_id: int | str, message_id: int, text: str, reply_markup: dict[str, Any] | None = None
    ) -> Any:
        params: dict[str, Any] = {
            "chat_id": chat_id,
            "message_id": message_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }
        if reply_markup:
            params["reply_markup"] = reply_markup
        return self.call("editMessageText", params)

    def answer_callback_query(self, callback_id: str, text: str = "", alert: bool = False) -> Any:
        return self.call("answerCallbackQuery", {"callback_query_id": callback_id, "text": text, "show_alert": alert})

    def set_my_commands(self, commands: list[tuple[str, str]]) -> Any:
        return self.call("setMyCommands", {"commands": [{"command": c, "description": d} for c, d in commands]})


def split_message(text: str, limit: int = MAX_MESSAGE_LEN) -> list[str]:
    """Split long text on line boundaries so each chunk fits into one Telegram message."""
    if len(text) <= limit:
        return [text]
    chunks: list[str] = []
    current = ""
    for line in text.splitlines(keepends=True):
        while len(line) > limit:  # a single giant line
            if current:
                chunks.append(current)
                current = ""
            chunks.append(line[:limit])
            line = line[limit:]
        if len(current) + len(line) > limit:
            chunks.append(current)
            current = ""
        current += line
    if current:
        chunks.append(current)
    return chunks


@dataclass
class OutgoingMessage:
    chat_id: int | str
    text: str
    reply_markup: dict[str, Any] | None = None
    silent: bool = False
    attempts: int = field(default=0)


class Outbox:
    """Background sender with rate limiting and retries."""

    def __init__(self, api: TelegramAPI, min_interval: float = 0.35, max_attempts: int = 8, max_queue: int = 500):
        self._api = api
        self._queue: queue.Queue[OutgoingMessage | None] = queue.Queue(maxsize=max_queue)
        self._min_interval = min_interval
        self._max_attempts = max_attempts
        self._thread = threading.Thread(target=self._run, name="tg-outbox", daemon=True)
        self._stop = threading.Event()

    def start(self) -> None:
        self._thread.start()

    def stop(self, flush_timeout: float = 5.0) -> None:
        deadline = time.monotonic() + flush_timeout
        while not self._queue.empty() and time.monotonic() < deadline:
            time.sleep(0.1)
        self._stop.set()
        try:
            self._queue.put_nowait(None)
        except queue.Full:
            pass
        self._thread.join(timeout=2)

    def send(
        self, chat_id: int | str, text: str, reply_markup: dict[str, Any] | None = None, silent: bool = False
    ) -> None:
        chunks = split_message(text)
        for i, chunk in enumerate(chunks):
            markup = reply_markup if i == len(chunks) - 1 else None
            try:
                self._queue.put_nowait(OutgoingMessage(chat_id, chunk, markup, silent))
            except queue.Full:
                log.warning("Telegram outbox is full, dropping message")

    def _run(self) -> None:
        last_sent = 0.0
        while not self._stop.is_set():
            msg = self._queue.get()
            if msg is None:
                break
            wait = self._min_interval - (time.monotonic() - last_sent)
            if wait > 0:
                time.sleep(wait)
            while not self._stop.is_set():
                msg.attempts += 1
                try:
                    self._api.send_message(msg.chat_id, msg.text, msg.reply_markup, msg.silent)
                    break
                except TelegramError as exc:
                    if exc.code is not None and exc.code != 429 and 400 <= exc.code < 500:
                        log.error("Telegram rejected message to %s: %s", msg.chat_id, exc)
                        break
                    if msg.attempts >= self._max_attempts:
                        log.error("Giving up sending message to %s: %s", msg.chat_id, exc)
                        break
                    delay = exc.retry_after or min(60, 2 ** msg.attempts)
                    log.warning("Telegram send failed (%s), retry in %ss", exc, delay)
                    self._stop.wait(delay)
            last_sent = time.monotonic()
