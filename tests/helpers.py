"""Shared test fakes."""

from __future__ import annotations

from typing import Any

from shelter_monitor.agent import config as config_mod

TOKEN = "123456:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"


def make_config(**sections: dict[str, Any]) -> config_mod.Config:
    raw: dict[str, Any] = {"telegram": {"token": TOKEN, "admin_ids": [111]}}
    for name, values in sections.items():
        raw.setdefault(name, {}).update(values)
    return config_mod.from_dict(raw)


class FakeOutbox:
    def __init__(self) -> None:
        self.sent: list[tuple[Any, str, Any, bool]] = []

    def send(self, chat_id: Any, text: str, reply_markup: Any = None, silent: bool = False) -> None:
        self.sent.append((chat_id, text, reply_markup, silent))


class FakeAPI:
    """Records Bot API calls instead of talking to Telegram."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self._next_id = 1

    def _record(self, method: str, **params: Any) -> dict[str, Any]:
        self.calls.append((method, params))
        self._next_id += 1
        return {"message_id": self._next_id}

    def send_message(self, chat_id: Any, text: str, reply_markup: Any = None, silent: bool = False) -> Any:
        return self._record("sendMessage", chat_id=chat_id, text=text, reply_markup=reply_markup)

    def edit_message_text(self, chat_id: Any, message_id: int, text: str, reply_markup: Any = None) -> Any:
        return self._record("editMessageText", chat_id=chat_id, message_id=message_id, text=text, reply_markup=reply_markup)

    def answer_callback_query(self, callback_id: str, text: str = "", alert: bool = False) -> Any:
        return self._record("answerCallbackQuery", text=text, alert=alert)

    def set_my_commands(self, commands: Any) -> Any:
        return self._record("setMyCommands")

    def get_updates(self, offset: Any, timeout: int = 50) -> list[Any]:
        return []

    def texts(self, method: str | None = None) -> list[str]:
        return [p.get("text", "") for m, p in self.calls if method is None or m == method]
