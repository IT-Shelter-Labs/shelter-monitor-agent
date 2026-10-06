"""Self-diagnostics: what the agent can and cannot see, and how to fix it."""

from __future__ import annotations

import glob
import os
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from shelter_monitor.agent.collectors.docker import DockerError
from shelter_monitor.agent.runtime import in_container, uses_host_network
from shelter_monitor.util import esc, fmt_duration, fmt_ts

if TYPE_CHECKING:  # pragma: no cover
    from shelter_monitor.agent.app import Agent

ICONS = {"ok": "✅", "warn": "⚠️", "fail": "❌", "off": "⚪️"}
CAP_SYS_ADMIN = 21


@dataclass
class Check:
    level: str   # ok | warn | fail | off
    title: str
    detail: str
    hint: str = ""

    def render(self) -> str:
        text = f"{ICONS[self.level]} <b>{esc(self.title)}</b>: {self.detail}"
        if self.hint:
            text += f"\n    💡 {self.hint}"
        return text


def has_capability(cap: int) -> bool:
    try:
        with open("/proc/self/status", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("CapEff:"):
                    return bool(int(line.split()[1], 16) & (1 << cap))
    except (OSError, ValueError):
        pass
    return False


def _journal_files() -> bool:
    return bool(glob.glob("/var/log/journal/*/*.journal") or glob.glob("/run/log/journal/*/*.journal"))


def collect(agent: "Agent") -> list[Check]:
    checks: list[Check] = []
    container = in_container()
    host_net = uses_host_network()

    if container:
        checks.append(Check("ok", "Запуск", "в Docker-контейнере"))
        if host_net:
            checks.append(Check("ok", "Сеть хоста", "используется (network_mode: host)"))
        else:
            checks.append(Check("fail", "Сеть хоста", "контейнер в собственной сети Docker — видны только соседние "
                                "контейнеры; трафик, LAN и входящие подключения показываются неверно",
                                "в docker-compose.yml у сервиса должен быть <code>network_mode: host</code> "
                                "(и не должно быть секции <code>networks:</code>)"))
        if agent.system.host_root:
            checks.append(Check("ok", "Файловая система хоста", f"{esc(agent.system.host_root)}, "
                                f"{esc(agent.system.os_name())}"))
        else:
            checks.append(Check("fail", "Файловая система хоста", "не подключена — диски и ОС показываются для контейнера",
                                "добавьте том <code>/:/host:ro,rslave</code>"))
    else:
        checks.append(Check("ok", "Запуск", "напрямую на хосте"))

    # systemd
    if agent.cfg.services.enabled:
        _, source, error = agent.service_probe.status(agent.services_units)
        if source == "systemd":
            checks.append(Check("ok", "systemd", "доступен"))
        elif source == "processes":
            checks.append(Check("warn", "systemd", f"недоступен: <code>{esc(error)}</code>. Статус сервисов — "
                                "приблизительно, по процессам хоста; уведомления о сервисах отключены",
                                "в Docker: том <code>/run/systemd:/run/systemd:ro</code>; проверьте "
                                "<code>docker compose logs</code>"))
        elif container:
            checks.append(Check("fail", "systemd", f"недоступен: <code>{esc(error)}</code>",
                                "тома <code>/run/systemd:/run/systemd:ro</code> и <code>/:/host:ro,rslave</code>"))
        else:
            checks.append(Check("fail", "systemd", f"недоступен: <code>{esc(error)}</code>",
                                "на машине без systemd выключите [services].enabled"))
    else:
        checks.append(Check("off", "systemd", "мониторинг сервисов выключен"))

    # SSH
    if agent.ssh is None:
        checks.append(Check("off", "SSH-входы", "выключено в конфигурации"))
    else:
        last = agent.storage.recent_ssh_logins(1)
        failures = agent.storage.ssh_failure_total(time.time() - 86400)
        src = agent.ssh.source_name
        err = agent.ssh.source_error
        detail = f"источник: {esc(src or 'ещё не выбран')}"
        if last:
            detail += f", последний вход {fmt_ts(last[0].ts)}"
        detail += f", неудачных за 24ч: {failures}"
        if err:
            checks.append(Check("fail", "SSH-входы", f"{detail}; ошибка: <code>{esc(err)}</code>",
                                "в Docker: тома <code>/var/log</code>, <code>/run/log/journal</code>, "
                                "<code>/etc/machine-id</code>"))
        elif src == "journal" and not _journal_files():
            checks.append(Check("warn", "SSH-входы", detail + "; файлы журнала не найдены",
                                "в Docker: тома <code>/var/log:/var/log:ro</code>, <code>/run/log/journal</code>, "
                                "<code>/etc/machine-id</code>"))
        else:
            checks.append(Check("ok", "SSH-входы", detail))

    # firewall
    if agent.firewall is None:
        checks.append(Check("off", "Файрвол (сканирования)", "выключено в конфигурации"))
    else:
        err = agent.firewall.source_error
        if err:
            checks.append(Check("fail", "Файрвол (сканирования)", f"ошибка чтения логов: <code>{esc(err)}</code>"))
        elif agent.firewall.last_hit:
            checks.append(Check("ok", "Файрвол (сканирования)",
                                f"источник: {agent.firewall.source_name}, последняя блокировка {fmt_ts(agent.firewall.last_hit)}"))
        else:
            checks.append(Check("warn", "Файрвол (сканирования)", "заблокированных пакетов в логах пока нет",
                                "включите файрвол и его логирование: <code>sudo ufw enable</code>, "
                                "<code>sudo ufw logging low</code>"))

    # docker
    if agent.docker is None:
        checks.append(Check("off", "Docker", "выключено в конфигурации"))
    elif not agent.docker.available():
        checks.append(Check("warn", "Docker", f"нет сокета {esc(agent.docker.socket_path)}",
                            "если Docker установлен: том <code>/var/run/docker.sock:/var/run/docker.sock</code>"))
    else:
        try:
            ver = agent.docker.version().get("Version", "?")
            count = len(agent.docker.containers())
            checks.append(Check("ok", "Docker", f"версия {esc(ver)}, контейнеров: {count}"))
        except DockerError as exc:
            checks.append(Check("fail", "Docker", esc(exc)))

    # LAN
    if agent.lan is None:
        checks.append(Check("off", "Устройства LAN", "выключено"))
    elif agent.lan.disabled_reason:
        checks.append(Check("fail", "Устройства LAN", esc(agent.lan.disabled_reason)))
    elif agent.lan.last_subnets:
        checks.append(Check("ok", "Устройства LAN", "подсети: " + esc(", ".join(agent.lan.last_subnets))))
    else:
        checks.append(Check("warn", "Устройства LAN", "подсеть ещё не определена (первое сканирование через ~20 с)"))

    # inbound connections
    if agent.connections is None:
        checks.append(Check("off", "Входящие подключения", "выключено"))
    elif not host_net:
        checks.append(Check("fail", "Входящие подключения", "не видны из сети контейнера", "нужен network_mode: host"))
    else:
        ports = ", ".join(str(p) for p in sorted(agent.connections.listening)) or "нет открытых портов из списка"
        checks.append(Check("ok", "Входящие подключения", f"слушаемые опасные порты: {esc(ports)}"))

    # heartbeat
    if agent.heartbeat is None:
        checks.append(Check("warn", "Heartbeat", "не настроен — о полном падении сервера никто не сообщит",
                            "бесплатно и без второго сервера: Healthchecks.io с интеграцией Telegram (см. README)"))
    elif agent.heartbeat.last_ok:
        checks.append(Check("ok", "Heartbeat", f"последняя отправка {fmt_duration(time.time() - agent.heartbeat.last_ok)} назад"))
    elif agent.heartbeat.last_error:
        checks.append(Check("fail", "Heartbeat", f"ошибка: <code>{esc(agent.heartbeat.last_error)}</code>"))
    else:
        checks.append(Check("warn", "Heartbeat", "ещё не отправлялся"))

    # actions on services
    acts = agent.actions
    if acts.services and acts.enabled:
        if container and not has_capability(CAP_SYS_ADMIN):
            checks.append(Check("warn", "Перезапуск сервисов", "systemd хоста откажет без CAP_SYS_ADMIN",
                                "раскомментируйте <code>- SYS_ADMIN</code> в cap_add docker-compose.yml"))
        elif not container and os.geteuid() != 0:
            checks.append(Check("ok", "Перезапуск сервисов", "через sudo",
                                "нужно правило: <code>shelter-agent sudoers | sudo tee /etc/sudoers.d/shelter-agent</code>"))
        else:
            checks.append(Check("ok", "Перезапуск сервисов", "доступен"))
    return checks


def problems(agent: "Agent") -> list[Check]:
    return [c for c in collect(agent) if c.level == "fail"]
