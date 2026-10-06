"""Predefined state-changing actions with two-step confirmation.

Security model:
  * there is no generic "run command" path - only the operations defined in OPS;
  * targets are limited by [actions] in the config file (not editable from Telegram):
    explicit service names, container name patterns, on/off switches for the rest;
  * every action needs an explicit confirmation by the same Telegram user within
    `confirm_timeout` seconds; confirmation tokens are random and single-use;
  * commands are executed with a fixed argv (no shell) or through the Docker API,
    and every result is written to the event log and broadcast to all admins.
"""

from __future__ import annotations

import fnmatch
import logging
import os
import secrets
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Callable

from shelter_monitor.agent.collectors.docker import DockerClient, DockerError
from shelter_monitor.agent.collectors.systemd import SYSTEMCTL_ENV
from shelter_monitor.agent.config import ActionsSection, normalize_unit
from shelter_monitor.agent.events import Event, EventBus
from shelter_monitor.agent.runtime import own_container_id
from shelter_monitor.util import esc, fmt_bytes

log = logging.getLogger(__name__)

ACTION_COOLDOWN = 30  # seconds between two actions on the same target

# op code (used in callback data) -> (label template, needs target)
OPS: dict[str, tuple[str, bool]] = {
    "sr": ("Перезапустить сервис {t}", True),
    "cr": ("Перезапустить контейнер {t}", True),
    "cs": ("Запустить контейнер {t}", True),
    "ct": ("Остановить контейнер {t}", True),
    "dp": ("Очистить Docker: неиспользуемые образы и кэш сборки", False),
    "ar": ("Перезапустить агент мониторинга", False),
}

# Extra warnings shown on the confirmation screen.
SERVICE_WARNINGS = {
    "docker.service": "Перезапуск Docker остановит и заново запустит ВСЕ контейнеры.",
    "ssh.service": "Текущие SSH-сессии не прервутся, но при ошибке в конфиге sshd новые входы будут невозможны.",
    "sshd.service": "Текущие SSH-сессии не прервутся, но при ошибке в конфиге sshd новые входы будут невозможны.",
    "networking.service": "Сервер может потерять сеть, и бот перестанет отвечать.",
    "systemd-networkd.service": "Сервер может потерять сеть, и бот перестанет отвечать.",
    "NetworkManager.service": "Сервер может потерять сеть, и бот перестанет отвечать.",
}


@dataclass
class PendingAction:
    token: str
    op: str
    target: str
    user_id: int
    expires: float

    @property
    def label(self) -> str:
        return OPS[self.op][0].format(t=self.target)


class ActionError(Exception):
    pass


class ActionManager:
    def __init__(self, cfg: ActionsSection, bus: EventBus, docker: DockerClient | None, enabled: bool = True,
                 monitored_units: list[str] | None = None, restart_agent: Callable[[], None] | None = None):
        self.cfg = cfg
        self.enabled = enabled
        services = [normalize_unit(u) for u in cfg.services]
        if cfg.allow_monitored_services:
            services += [normalize_unit(u) for u in monitored_units or []]
        self.services = list(dict.fromkeys(services))  # dedupe, keep order
        self.container_patterns = list(cfg.containers)
        self._bus = bus
        self._docker = docker
        self._restart_agent = restart_agent
        self._pending: dict[str, PendingAction] = {}
        self._last_run: dict[str, float] = {}
        self._lock = threading.Lock()
        self._exec_lock = threading.Lock()
        self.systemctl = shutil.which("systemctl") or "/usr/bin/systemctl"
        self.own_container = own_container_id()

    # -- what is allowed ---------------------------------------------------------------

    def container_allowed(self, name: str) -> bool:
        return any(fnmatch.fnmatch(name, p) for p in self.container_patterns)

    def is_own_container(self, name_or_id: str) -> bool:
        return bool(self.own_container) and (self.own_container.startswith(name_or_id) or name_or_id == self.own_container)

    def check(self, op: str, target: str = "") -> None:
        """Raise ActionError if the operation is not permitted by the config."""
        if not self.enabled:
            raise ActionError("Действия отключены в конфигурации ([telegram].allow_actions = false)")
        if op not in OPS:
            raise ActionError("Неизвестное действие")
        if op == "sr":
            if target not in self.services:
                raise ActionError("Сервис не входит в список разрешённых ([actions].services)")
        elif op in ("cr", "cs", "ct"):
            if self._docker is None:
                raise ActionError("Мониторинг Docker выключен")
            if not self.container_allowed(target):
                raise ActionError("Контейнер не входит в список разрешённых ([actions].containers)")
            if op == "ct" and not self.cfg.container_stop:
                raise ActionError("Остановка контейнеров запрещена ([actions].container_stop = false)")
            if op == "ct" and self.is_own_container(target):
                raise ActionError("Нельзя остановить контейнер самого агента — бот перестанет отвечать")
        elif op == "dp":
            if self._docker is None or not self.cfg.docker_prune:
                raise ActionError("Очистка Docker запрещена или Docker не настроен")
        elif op == "ar" and not self.cfg.agent_restart:
            raise ActionError("Перезапуск агента запрещён ([actions].agent_restart = false)")

    def allowed(self, op: str, target: str = "") -> bool:
        try:
            self.check(op, target)
            return True
        except ActionError:
            return False

    @staticmethod
    def callback(op: str, target: str = "") -> str | None:
        data = f"a:{op}:{target}"
        return data if len(data.encode()) <= 64 else None  # Telegram limit for callback_data

    def service_buttons(self, unit: str) -> list[list[tuple[str, str]]]:
        cb = self.callback("sr", unit)
        return [[("🔁 Перезапустить", cb)]] if cb and self.allowed("sr", unit) else []

    def container_buttons(self, name: str, state: str = "") -> list[list[tuple[str, str]]]:
        row: list[tuple[str, str]] = []
        if state != "running" and self.allowed("cs", name) and (cb := self.callback("cs", name)):
            row.append(("▶️ Запустить", cb))
        if self.allowed("cr", name) and (cb := self.callback("cr", name)):
            row.append(("🔁 Перезапустить", cb))
        if self.cfg.container_logs and (cb := f"cl:{name}") and len(cb.encode()) <= 64:
            row.append(("📋 Логи", cb))
        return [row] if row else []

    # -- confirmation flow --------------------------------------------------------------

    def request(self, op: str, target: str, user_id: int) -> PendingAction:
        self.check(op, target)
        now = time.time()
        with self._lock:
            for tok in [t for t, p in self._pending.items() if p.expires < now]:
                del self._pending[tok]
            action = PendingAction(secrets.token_urlsafe(9), op, target, user_id, now + self.cfg.confirm_timeout)
            self._pending[action.token] = action
        return action

    def warning(self, action: PendingAction) -> str:
        if action.op == "sr":
            return SERVICE_WARNINGS.get(action.target, "")
        if action.op == "ct":
            return "Контейнер останется остановленным, пока его не запустят."
        if action.op == "cr" and self.is_own_container(action.target):
            return "Это контейнер самого агента: бот будет недоступен несколько секунд."
        if action.op == "dp":
            return "Удаляются только образы без тегов и кэш сборки. Контейнеры, тома и используемые образы не трогаются."
        if action.op == "ar":
            return "Агент завершится и будет запущен заново (systemd / политикой restart Docker)."
        return ""

    def cancel(self, token: str, user_id: int) -> PendingAction | None:
        with self._lock:
            action = self._pending.get(token)
            if action and action.user_id == user_id:
                return self._pending.pop(token)
        return None

    def cancel_expired(self, token: str) -> bool:
        """Drop a request whose time is up. True if it was still pending (nobody answered)."""
        with self._lock:
            action = self._pending.get(token)
            if action is not None and action.expires <= time.time() + 1:
                del self._pending[token]
                return True
        return False

    def confirm(self, token: str, user_id: int) -> tuple[PendingAction, bool, str]:
        """Execute a confirmed action. Returns (action, ok, message)."""
        with self._lock:
            action = self._pending.get(token)
            if action is None:
                raise ActionError("Запрос не найден или уже выполнен")
            if action.user_id != user_id:
                raise ActionError("Подтвердить действие может только тот, кто его запросил")
            del self._pending[token]
            if action.expires < time.time():
                raise ActionError("Время на подтверждение истекло, запросите действие заново")
            self.check(action.op, action.target)  # config may have changed meanwhile
            key = f"{action.op}:{action.target}"
            last = self._last_run.get(key, 0)
            if time.time() - last < ACTION_COOLDOWN:
                raise ActionError(f"Это действие уже выполнялось недавно, подождите {ACTION_COOLDOWN} с")
            self._last_run[key] = time.time()

        if not self._exec_lock.acquire(timeout=1):
            raise ActionError("Другое действие ещё выполняется, попробуйте позже")
        try:
            ok, output = self._execute(action)
        finally:
            self._exec_lock.release()

        self._bus.emit(Event(
            "agent", "warning" if ok else "critical", "action_executed" if ok else "action_failed",
            f"{'✅' if ok else '❌'} {action.label}",
            f"Инициатор: <code>{user_id}</code>" + (f"\n<pre>{esc(output[-1500:])}</pre>" if output else ""),
            data={"op": action.op, "target": action.target, "user_id": user_id, "ok": ok, "notify": True},
        ))
        if ok and action.op == "ar" and self._restart_agent:
            threading.Timer(2.0, self._restart_agent).start()  # let the reply go out first
        return action, ok, output

    def _execute(self, action: PendingAction) -> tuple[bool, str]:
        log.warning("executing action %s %s requested by %s", action.op, action.target, action.user_id)
        if action.op == "sr":
            return self._restart_service(action.target)
        if action.op == "ar":
            return True, "Агент перезапускается…"
        assert self._docker is not None
        try:
            if action.op == "cr":
                self._docker.restart(action.target)
            elif action.op == "cs":
                self._docker.start(action.target)
            elif action.op == "ct":
                self._docker.stop(action.target)
            elif action.op == "dp":
                removed, reclaimed = self._docker.prune()
                return True, f"Удалено образов: {removed}, освобождено {fmt_bytes(reclaimed)}"
            return True, ""
        except DockerError as exc:
            return False, str(exc)

    # -- services -------------------------------------------------------------------

    def _use_sudo(self) -> bool:
        if self.cfg.use_sudo == "always":
            return True
        if self.cfg.use_sudo == "never":
            return False
        return os.geteuid() != 0

    def service_argv(self, unit: str) -> list[str]:
        # Must match the sudoers rule generated by `shelter-agent sudoers` exactly.
        argv = [self.systemctl, "restart", unit]
        if self._use_sudo():
            argv = [shutil.which("sudo") or "/usr/bin/sudo", "-n", *argv]
        return argv

    def _restart_service(self, unit: str) -> tuple[bool, str]:
        try:
            proc = subprocess.run(self.service_argv(unit), capture_output=True, text=True, timeout=120, check=False,
                                  env=SYSTEMCTL_ENV)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return False, str(exc)
        output = (proc.stdout + proc.stderr).strip()
        if proc.returncode != 0 and ("Access denied" in output or "Interactive authentication" in output):
            output += ("\nВ Docker раскомментируйте SYS_ADMIN в docker-compose.yml; без Docker установите правило sudoers "
                       "(shelter-agent sudoers).")
        elif proc.returncode != 0 and "password is required" in output:
            output += "\nУстановите правило sudoers: shelter-agent sudoers | sudo tee /etc/sudoers.d/shelter-agent"
        return proc.returncode == 0, output

    def sudoers_rules(self, user: str = "shelter") -> str:
        lines = [
            "# Generated by `shelter-agent sudoers`: allows the agent to restart ONLY these units.",
            "# Install: shelter-agent sudoers | sudo tee /etc/sudoers.d/shelter-agent && sudo visudo -cf /etc/sudoers.d/shelter-agent",
        ]
        for unit in self.services:
            lines.append(f"{user} ALL=(root) NOPASSWD: {self.systemctl} restart {unit}")
        if not self.services:
            lines.append("# no services are allowed in [actions] - nothing to allow")
        return "\n".join(lines) + "\n"
