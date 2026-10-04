"""Watchdog configuration."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any

from shelter_monitor.util import load_toml

DEFAULT_CONFIG_PATH = "/etc/shelter-watchdog/config.toml"
AGENT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,63}$")


class ConfigError(Exception):
    pass


@dataclass
class AgentEntry:
    id: str
    token: str
    name: str = ""
    timeout: int = 0  # 0 -> watchdog.default_timeout

    @property
    def display(self) -> str:
        return self.name or self.id


@dataclass
class WatchdogConfig:
    listen: str = "0.0.0.0"
    port: int = 8787
    data_file: str = "/var/lib/shelter-watchdog/state.json"
    check_interval: int = 30
    default_timeout: int = 300
    remind_interval: int = 0
    status_token: str = ""
    log_level: str = "INFO"
    telegram_token: str = ""
    telegram_api_url: str = "https://api.telegram.org"
    telegram_proxy: str = ""
    chat_ids: list[int] = field(default_factory=list)
    agents: list[AgentEntry] = field(default_factory=list)

    def timeout_for(self, agent: AgentEntry) -> int:
        return agent.timeout or self.default_timeout


def _get(table: dict[str, Any], key: str, typ: type, default: Any, where: str) -> Any:
    value = table.get(key, default)
    if typ is int and (isinstance(value, bool) or not isinstance(value, int)):
        raise ConfigError(f"{where}.{key}: expected integer")
    if typ is str and not isinstance(value, str):
        raise ConfigError(f"{where}.{key}: expected string")
    return value


def from_dict(raw: dict[str, Any]) -> WatchdogConfig:
    w = raw.get("watchdog", {})
    tg = raw.get("telegram", {})
    cfg = WatchdogConfig(
        listen=_get(w, "listen", str, "0.0.0.0", "[watchdog]"),
        port=_get(w, "port", int, 8787, "[watchdog]"),
        data_file=_get(w, "data_file", str, WatchdogConfig.data_file, "[watchdog]"),
        check_interval=_get(w, "check_interval", int, 30, "[watchdog]"),
        default_timeout=_get(w, "default_timeout", int, 300, "[watchdog]"),
        remind_interval=_get(w, "remind_interval", int, 0, "[watchdog]"),
        status_token=_get(w, "status_token", str, "", "[watchdog]"),
        log_level=_get(w, "log_level", str, "INFO", "[watchdog]"),
        telegram_token=_get(tg, "token", str, "", "[telegram]"),
        telegram_api_url=_get(tg, "api_url", str, "https://api.telegram.org", "[telegram]"),
        telegram_proxy=_get(tg, "proxy", str, "", "[telegram]"),
        chat_ids=list(tg.get("chat_ids", [])),
    )
    token_file = tg.get("token_file", "")
    if token_file and not cfg.telegram_token:
        try:
            with open(token_file, encoding="utf-8") as fh:
                cfg.telegram_token = fh.read().strip()
        except OSError as exc:
            raise ConfigError(f"[telegram].token_file: {exc}") from None
    cfg.telegram_token = os.environ.get("SHELTER_TELEGRAM_TOKEN", cfg.telegram_token).strip()

    errors = []
    if not cfg.telegram_token:
        errors.append("[telegram].token is required")
    if not cfg.chat_ids or not all(isinstance(c, int) and not isinstance(c, bool) for c in cfg.chat_ids):
        errors.append("[telegram].chat_ids must be a non-empty list of integers")
    if cfg.default_timeout < 30:
        errors.append("[watchdog].default_timeout must be >= 30 seconds")
    if cfg.check_interval < 5:
        errors.append("[watchdog].check_interval must be >= 5 seconds")

    ids: set[str] = set()
    tokens: set[str] = set()
    for i, entry in enumerate(raw.get("agents", [])):
        where = f"[[agents]] #{i + 1}"
        if not isinstance(entry, dict):
            errors.append(f"{where}: must be a table")
            continue
        agent = AgentEntry(
            id=str(entry.get("id", "")), token=str(entry.get("token", "")),
            name=str(entry.get("name", "")), timeout=int(entry.get("timeout", 0)),
        )
        if not AGENT_ID_RE.match(agent.id):
            errors.append(f"{where}: invalid id {agent.id!r}")
        if len(agent.token) < 24:
            errors.append(f"{where}: token must be at least 24 characters (use `openssl rand -hex 32`)")
        if agent.id in ids:
            errors.append(f"{where}: duplicate id {agent.id!r}")
        if agent.token in tokens:
            errors.append(f"{where}: duplicate token")
        if agent.timeout and agent.timeout < 30:
            errors.append(f"{where}: timeout must be >= 30 seconds")
        ids.add(agent.id)
        tokens.add(agent.token)
        cfg.agents.append(agent)
    if not cfg.agents:
        errors.append("at least one [[agents]] entry is required")
    if errors:
        raise ConfigError("invalid configuration:\n  - " + "\n  - ".join(errors))
    return cfg


def load(path: str = DEFAULT_CONFIG_PATH) -> WatchdogConfig:
    if not os.path.exists(path):
        raise ConfigError(f"config file not found: {path}")
    try:
        return from_dict(load_toml(path))
    except (ValueError, RuntimeError) as exc:
        raise ConfigError(f"{path}: {exc}") from None
