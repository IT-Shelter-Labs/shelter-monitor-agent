"""Allowlisted state-changing actions with two-step confirmation.

Security model:
  * there is no generic "run command" path - only the action kinds defined here;
  * targets must be listed in [actions] of the config file (not editable from Telegram);
  * every action needs an explicit confirmation by the same Telegram user within
    `confirm_timeout` seconds; confirmation tokens are random and single-use;
  * commands are executed with a fixed argv (no shell), and every request / result
    is written to the event log and broadcast to all admins.
"""

from __future__ import annotations

import logging
import os
import secrets
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Any

from shelter_monitor.agent.collectors.docker import DockerClient, DockerError
from shelter_monitor.agent.collectors.systemd import SYSTEMCTL_ENV
from shelter_monitor.agent.config import ActionsSection, normalize_unit
from shelter_monitor.agent.events import Event, EventBus
from shelter_monitor.util import esc

log = logging.getLogger(__name__)

ACTION_COOLDOWN = 30  # seconds between two actions on the same target


@dataclass
class PendingAction:
    token: str
    kind: str        # "service" | "container"
    target: str
    user_id: int
    expires: float

    @property
    def label(self) -> str:
        what = "сервис" if self.kind == "service" else "контейнер"
        return f"Перезапустить {what} {self.target}"


class ActionError(Exception):
    pass


class ActionManager:
    def __init__(self, cfg: ActionsSection, bus: EventBus, docker: DockerClient | None, enabled: bool = True):
        self.cfg = cfg
        self.enabled = enabled
        self.services = [normalize_unit(u) for u in cfg.services]
        self.containers = list(cfg.containers)
        self._bus = bus
        self._docker = docker
        self._pending: dict[str, PendingAction] = {}
        self._last_run: dict[str, float] = {}
        self._lock = threading.Lock()
        self._exec_lock = threading.Lock()
        self.systemctl = shutil.which("systemctl") or "/usr/bin/systemctl"

    def target_by_index(self, kind: str, index: int) -> str:
        items = self.services if kind == "service" else self.containers
        if not 0 <= index < len(items):
            raise ActionError("Такого объекта нет в списке разрешённых")
        return items[index]

    def request(self, kind: str, target: str, user_id: int) -> PendingAction:
        if not self.enabled:
            raise ActionError("Действия отключены в конфигурации ([telegram].allow_actions = false)")
        allowed = self.services if kind == "service" else self.containers if kind == "container" else []
        if target not in allowed:
            raise ActionError("Объект не входит в список разрешённых")
        now = time.time()
        with self._lock:
            for tok in [t for t, p in self._pending.items() if p.expires < now]:
                del self._pending[tok]
            action = PendingAction(secrets.token_urlsafe(9), kind, target, user_id, now + self.cfg.confirm_timeout)
            self._pending[action.token] = action
        return action

    def cancel(self, token: str, user_id: int) -> PendingAction | None:
        with self._lock:
            action = self._pending.get(token)
            if action and action.user_id == user_id:
                return self._pending.pop(token)
        return None

    def confirm(self, token: str, user_id: int) -> tuple[PendingAction, str]:
        with self._lock:
            action = self._pending.get(token)
            if action is None:
                raise ActionError("Запрос не найден или уже выполнен")
            if action.user_id != user_id:
                raise ActionError("Подтвердить действие может только тот, кто его запросил")
            del self._pending[token]
            if action.expires < time.time():
                raise ActionError("Время на подтверждение истекло, запросите действие заново")
            key = f"{action.kind}:{action.target}"
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
            data={"kind": action.kind, "target": action.target, "user_id": user_id, "ok": ok, "notify": True},
        ))
        return action, ("Готово" if ok else "Ошибка") + (f": {output[-300:]}" if output else "")

    def _execute(self, action: PendingAction) -> tuple[bool, str]:
        log.warning("executing action %s %s requested by %s", action.kind, action.target, action.user_id)
        if action.kind == "service":
            return self._restart_service(action.target)
        if action.kind == "container":
            if self._docker is None:
                return False, "Docker не настроен"
            try:
                self._docker.restart(action.target)
                return True, ""
            except DockerError as exc:
                return False, str(exc)
        return False, "unknown action"  # pragma: no cover

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
        return proc.returncode == 0, output

    def sudoers_rules(self, user: str = "shelter") -> str:
        lines = [
            "# Generated by `shelter-agent sudoers`: allows the agent to restart ONLY these units.",
            "# Install: shelter-agent sudoers | sudo tee /etc/sudoers.d/shelter-agent && sudo visudo -cf /etc/sudoers.d/shelter-agent",
        ]
        for unit in self.services:
            lines.append(f"{user} ALL=(root) NOPASSWD: {self.systemctl} restart {unit}")
        if not self.services:
            lines.append("# [actions].services is empty - nothing to allow")
        return "\n".join(lines) + "\n"

    def describe(self) -> dict[str, Any]:
        return {"services": self.services, "containers": self.containers, "enabled": self.enabled}
