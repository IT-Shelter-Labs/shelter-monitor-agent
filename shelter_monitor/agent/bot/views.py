"""Telegram screens. Each view returns (html_text, inline_keyboard_rows).

Callback data conventions (see bot.py):
  v:<view>[:<arg>]  re-render a view in the same message
  o:<view>          open a view as a NEW message (used under notifications)
  c:<container>     container card              cl:<container>  container logs
  a:<op>:<target>   request a confirmed action  cf:/cx:<token>  confirm / cancel
  dev:<op>:<mac>    device action under a notification, devv:<op>:<mac> - inside the device list
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

from shelter_monitor import __version__
from shelter_monitor.agent import diagnostics
from shelter_monitor.agent.collectors.docker import Container, DockerError
from shelter_monitor.agent.events import CATEGORIES
from shelter_monitor.agent.lan import is_random_mac
from shelter_monitor.agent.notifier import SEVERITY_ICON
from shelter_monitor.agent.runtime import in_container, uses_host_network
from shelter_monitor.agent.security import port_label
from shelter_monitor.util import bar, esc, fmt_bytes, fmt_duration, fmt_rate, fmt_ts

if TYPE_CHECKING:  # pragma: no cover
    from shelter_monitor.agent.app import Agent

Rows = list[list[tuple[str, str]]]
View = tuple[str, Rows]

MAIN_MENU: Rows = [
    [("🔄 Обновить", "v:status"), ("📊 Метрики", "v:metrics")],
    [("🐳 Docker", "v:docker"), ("⚙️ Сервисы", "v:services")],
    [("🔑 SSH", "v:ssh"), ("🛡 Безопасность", "v:security")],
    [("📡 Устройства LAN", "v:devices"), ("📜 События", "v:events")],
    [("🛠 Действия", "v:actions"), ("🔔 Уведомления", "v:notify")],
    [("🔍 Проверить всё", "chk"), ("🩺 Диагностика", "v:diag")],
]

BACK: list[tuple[str, str]] = [("⬅️ Меню", "v:status")]
CONTAINERS_PER_PAGE = 10

# packages providing common units (for the "how to install" hint)
INSTALL_HINTS = {
    "ssh.service": "openssh-server", "sshd.service": "openssh-server", "cron.service": "cron",
    "docker.service": "docker.io", "nginx.service": "nginx", "fail2ban.service": "fail2ban",
    "ufw.service": "ufw", "apache2.service": "apache2", "postgresql.service": "postgresql",
    "redis-server.service": "redis-server", "rsyslog.service": "rsyslog", "chrony.service": "chrony",
}

HELP_TEXT = """<b>Shelter Monitor Agent</b> — мониторинг сервера

/status — сводка и активные проблемы
/metrics — CPU, память, диски, сеть, температура
/docker — контейнеры: статус, логи, перезапуск
/services — сервисы systemd
/ssh — SSH-входы и неудачные попытки
/security — кто стучался: SSH, файрвол, входящие подключения, новые устройства
/devices — устройства в локальной сети
/events — последние события
/check — выполнить все проверки прямо сейчас
/diag — диагностика: что агент видит и что нужно донастроить
/notify — настройки уведомлений
/mute [30m|2h|1d], /unmute — выключить / включить уведомления
/actions — действия: перезапуск сервисов и контейнеров, очистка Docker, перезапуск агента
/id — ваш Telegram ID и ID чата

<b>«Проверить всё»</b> — агент не дожидается своего расписания (обычно раз в 30–300 с) и сразу
проверяет ресурсы, сервисы, контейнеры, связь и сеть. Результат — сводка: какие проблемы
появились, какие исчезли.

Бот не выполняет произвольные команды: доступны только заранее определённые действия
для разрешённых в конфигурации объектов, и каждое требует подтверждения."""


def _ago(ts: float) -> str:
    return fmt_duration(time.time() - ts) + " назад"


def _container_icon(c: Container) -> str:
    if c.state == "running":
        return "⚠️" if c.health == "unhealthy" else "🟢"
    if c.state in ("restarting", "paused", "created"):
        return "🟡"
    return "🔴"


def _cb_container(prefix: str, c: Container) -> str:
    data = f"{prefix}:{c.name}"
    return data if len(data.encode()) <= 64 else f"{prefix}:{c.id}"


def _services_line(agent: "Agent") -> str:
    if not agent.services_units:
        return ""
    statuses, source, _ = agent.service_probe.status(agent.services_units)
    if not source:
        return "⚙️ Сервисы: ❌ нет доступа к systemd — /diag"
    existing = [u for u in statuses if u.exists]
    ok = sum(1 for u in existing if u.ok)
    approx = " (приблизительно)" if source == "processes" else ""
    return f"⚙️ Сервисы: {ok}/{len(existing)} работают{approx}"


# --- status ---------------------------------------------------------------------------


def status_view(agent: "Agent") -> View:
    snap = agent.snapshot()
    lines = [f"🖥 <b>{esc(agent.host)}</b> · {esc(snap.os_name)}",
             f"⏱ Аптайм: {fmt_duration(snap.uptime)}" + (f" · IP <code>{esc(snap.primary_ip)}</code>" if snap.primary_ip else "")]

    alerts = agent.tracker.active()
    if alerts:
        lines.append(f"\n🔴 <b>Активные проблемы: {len(alerts)}</b>")
        for a in alerts[:10]:
            lines.append(f"{SEVERITY_ICON.get(a.severity, '')} {esc(a.title)} <i>({_ago(a.since)})</i>")
    else:
        lines.append("\n🟢 <b>Проблем не обнаружено</b>")

    mem = snap.memory
    metric_lines = [
        f"CPU  {bar(snap.cpu_percent)} {snap.cpu_percent:3.0f}%",
        f"RAM  {bar(mem.percent)} {mem.percent:3.0f}%",
    ]
    for d in sorted(snap.disks, key=lambda d: -d.percent)[:3]:
        metric_lines.append(f"Disk {bar(d.percent)} {d.percent:3.0f}% {d.mount}")
    lines.append("\n<code>" + esc("\n".join(metric_lines)) + "</code>")
    lines.append(f"Load: {snap.load[0]:.2f} {snap.load[1]:.2f} {snap.load[2]:.2f} (ядер: {snap.cpu_count})"
                 + (f" · 🌡 {snap.temperature:.0f}°C" if snap.temperature is not None else ""))

    if agent.docker is not None and agent.docker.available():
        try:
            containers = agent.docker.containers()
            running = sum(1 for c in containers if c.state == "running")
            unhealthy = sum(1 for c in containers if c.health == "unhealthy")
            lines.append(f"🐳 Docker: {running}/{len(containers)} запущено" + (f", ⚠️ unhealthy: {unhealthy}" if unhealthy else ""))
        except DockerError:
            lines.append("🐳 Docker: ❌ недоступен")
    services = _services_line(agent)
    if services:
        lines.append(services)

    logins = agent.storage.recent_ssh_logins(1)
    failures = agent.storage.ssh_failure_total(time.time() - 86400)
    if logins:
        last = logins[0]
        lines.append(f"🔑 Последний SSH-вход: {esc(last.user)} с <code>{esc(last.ip)}</code> ({fmt_ts(last.ts)})")
    if failures:
        lines.append(f"🚫 Неудачных SSH-попыток за 24ч: {failures}")
    if agent.firewall is not None:
        blocked = agent.firewall.stats(time.time() - 86400)["total"]
        if blocked:
            lines.append(f"🛡 Заблокировано файрволом за 24ч: {blocked}")

    if agent.heartbeat is not None:
        hb = agent.heartbeat
        if hb.last_ok:
            lines.append(f"💓 Heartbeat: OK, {_ago(hb.last_ok)}")
        elif hb.last_error:
            lines.append(f"💔 Heartbeat: ошибка — {esc(hb.last_error)[:100]}")
    if agent.settings.is_muted():
        lines.append(f"🔕 Уведомления выключены до {fmt_ts(agent.settings.mute_until)}")
    lines.append(f"\n<i>Обновлено {fmt_ts(time.time(), with_date=False)}</i>")
    return "\n".join(lines), MAIN_MENU


def check_result_view(agent: "Agent", result: dict[str, Any]) -> View:
    """Shown after "🔍 Проверить всё": what the immediate check found, then the status."""
    if result.get("busy"):
        head = "⏳ Проверка уже выполняется, показываю текущее состояние."
    else:
        head = f"🔍 <b>Проверка выполнена</b> за {result['took']:.1f} с: ресурсы, сервисы, Docker, связь, сеть."
        if result["new"]:
            head += "\n🆕 Новые проблемы: " + "; ".join(esc(a.title) for a in result["new"])
        if result["resolved"]:
            head += "\n✅ Решено: " + "; ".join(esc(a.title) for a in result["resolved"])
        if not result["new"] and not result["resolved"]:
            head += "\nИзменений нет."
    text, rows = status_view(agent)
    return head + "\n\n" + text, rows


# --- metrics -----------------------------------------------------------------------------


def metrics_view(agent: "Agent") -> View:
    snap = agent.snapshot(net_window=1.0)
    mem = snap.memory
    lines = [f"📊 <b>Метрики · {esc(agent.host)}</b>",
             f"{esc(snap.os_name)}, ядро {esc(snap.kernel)}",
             f"Аптайм: {fmt_duration(snap.uptime)}", "",
             f"<b>CPU:</b> {snap.cpu_percent:.1f}% (ядер: {snap.cpu_count})",
             f"<b>Load average:</b> {snap.load[0]:.2f} / {snap.load[1]:.2f} / {snap.load[2]:.2f}",
             f"<b>RAM:</b> {mem.percent:.1f}% — {fmt_bytes(mem.used)} из {fmt_bytes(mem.total)} "
             f"(доступно {fmt_bytes(mem.available)})"]
    if mem.swap_total:
        lines.append(f"<b>Swap:</b> {mem.swap_percent:.1f}% — {fmt_bytes(mem.swap_used)} из {fmt_bytes(mem.swap_total)}")
    else:
        lines.append("<b>Swap:</b> нет")
    if snap.temperature is not None:
        lines.append(f"<b>Температура:</b> {snap.temperature:.1f}°C")
    lines.append("\n<b>Диски:</b>")
    for d in snap.disks:
        lines.append(f"<code>{esc(d.mount)}</code> {bar(d.percent, 8)} {d.percent:.0f}% — свободно "
                     f"{fmt_bytes(d.free)} из {fmt_bytes(d.total)} ({esc(d.fstype)})")
    if not snap.disks:
        lines.append("— не найдено (в Docker нужен том <code>/:/host:ro,rslave</code>)")
    if snap.net:
        lines.append("\n<b>Сеть:</b>")
        for n in snap.net:
            lines.append(f"<code>{esc(n.iface)}</code> ↓ {fmt_rate(n.rx_rate)} ↑ {fmt_rate(n.tx_rate)} "
                         f"(всего ↓ {fmt_bytes(n.rx_bytes)} ↑ {fmt_bytes(n.tx_bytes)})")
    if agent.connectivity is not None and agent.connectivity.last_results:
        lines.append("\n<b>Связь:</b>")
        for target, latency in agent.connectivity.last_results.items():
            state = f"✅ {latency:.0f} мс" if latency is not None else "❌ недоступен"
            lines.append(f"<code>{esc(target)}</code> {state}")
    if in_container():
        problems = []
        if not uses_host_network():
            problems.append("нет сети хоста")
        if not agent.system.host_root:
            problems.append("не подключена файловая система хоста")
        if problems:
            lines.append("\n⚠️ Часть данных относится к контейнеру, а не к серверу (" + ", ".join(problems) + ") — /diag")
    return "\n".join(lines), [[("🔄 Обновить", "v:metrics"), *BACK]]


# --- docker ---------------------------------------------------------------------------


def docker_view(agent: "Agent", page: int = 0) -> View:
    rows: Rows = []
    if agent.docker is None:
        return "🐳 Мониторинг Docker выключен в конфигурации.", [BACK]
    if not agent.docker.available():
        return (f"🐳 Docker не найден (нет сокета <code>{esc(agent.docker.socket_path)}</code>).\n"
                "В Docker-режиме нужен том <code>/var/run/docker.sock:/var/run/docker.sock</code>."), [BACK]
    try:
        containers = agent.docker.containers()
    except DockerError as exc:
        return f"🐳 Docker недоступен: {esc(exc)}", [[("🔄 Обновить", "v:docker"), *BACK]]
    if not containers:
        return "🐳 Контейнеров нет.", [[("🔄 Обновить", "v:docker"), *BACK]]
    running = sum(1 for c in containers if c.state == "running")
    pages = max(1, (len(containers) + CONTAINERS_PER_PAGE - 1) // CONTAINERS_PER_PAGE)
    page = max(0, min(page, pages - 1))
    chunk = containers[page * CONTAINERS_PER_PAGE:(page + 1) * CONTAINERS_PER_PAGE]
    lines = [f"🐳 <b>Docker</b>: {running}/{len(containers)} запущено"
             + (f" · стр. {page + 1}/{pages}" if pages > 1 else ""), ""]
    for c in chunk:
        lines.append(f"{_container_icon(c)} <b>{esc(c.name)}</b> — {esc(c.status)}")
    lines.append("\nНажмите на контейнер, чтобы посмотреть логи или перезапустить его.")
    buttons = [(f"{_container_icon(c)} {c.name[:28]}", _cb_container("c", c)) for c in chunk]
    for i in range(0, len(buttons), 2):
        rows.append(buttons[i:i + 2])
    nav: list[tuple[str, str]] = []
    if page > 0:
        nav.append(("◀️", f"v:docker:{page - 1}"))
    if page < pages - 1:
        nav.append(("▶️", f"v:docker:{page + 1}"))
    if nav:
        rows.append(nav)
    extra: list[tuple[str, str]] = [("🔄 Обновить", f"v:docker:{page}")]
    if agent.actions.allowed("dp"):
        extra.append(("🧹 Очистить", "a:dp:"))
    rows.append(extra)
    rows.append(BACK)
    return "\n".join(lines), rows


def container_view(agent: "Agent", name: str) -> View:
    back: Rows = [[("🔄 Обновить", f"c:{name}"), ("⬅️ К списку", "v:docker")]]
    if agent.docker is None:
        return "🐳 Мониторинг Docker выключен.", [BACK]
    try:
        c = agent.docker.container(name)
    except DockerError as exc:
        return f"🐳 Docker недоступен: {esc(exc)}", back
    if c is None:
        return f"Контейнер <code>{esc(name)}</code> не найден (удалён?).", [[("⬅️ К списку", "v:docker")]]
    lines = [f"{_container_icon(c)} <b>{esc(c.name)}</b>", f"Состояние: <b>{esc(c.state)}</b>", f"Статус: {esc(c.status)}",
             f"Образ: <code>{esc(c.image)}</code>", f"ID: <code>{esc(c.id)}</code>"]
    if c.health:
        lines.append(f"Health: {esc(c.health)}")
    if agent.actions.is_own_container(c.id):
        lines.append("\nℹ️ Это контейнер самого агента мониторинга.")
    rows = agent.actions.container_buttons(c.name, c.state)
    if c.state == "running" and agent.actions.allowed("ct", c.name) and (cb := agent.actions.callback("ct", c.name)):
        rows.append([("⏹ Остановить", cb)])
    if not rows:
        lines.append("\nДействия с этим контейнером не разрешены ([actions].containers).")
    return "\n".join(lines), rows + back


def container_logs_view(agent: "Agent", name: str, tail: int = 40) -> View:
    rows: Rows = [[("🔄 Обновить", f"cl:{name}"), ("🐳 Контейнер", f"c:{name}")]]
    if agent.docker is None or not agent.cfg.actions.container_logs:
        return "Просмотр логов контейнеров отключён.", []
    try:
        logs = agent.docker.logs(name, tail)
    except DockerError as exc:
        return f"Не удалось получить логи <code>{esc(name)}</code>: {esc(exc)}", rows
    text = logs.strip() or "(пусто)"
    if len(text) > 3500:
        text = "…" + text[-3500:]
    return f"📋 <b>Логи {esc(name)}</b> (последние {tail} строк)\n<pre>{esc(text)}</pre>", rows


# --- services --------------------------------------------------------------------------


def services_view(agent: "Agent") -> View:
    rows: Rows = []
    units = agent.services_units or []
    lines = ["⚙️ <b>Сервисы</b>\n"]
    statuses, source, error = agent.service_probe.status(units)
    restart_buttons: list[tuple[str, str]] = []
    if error:
        lines.append(f"❌ Нет доступа к systemd: <code>{esc(error)}</code>")
        if source == "processes":
            lines.append("Статус ниже определён <b>приблизительно</b> — по процессам хоста.\n")
        else:
            lines.append("Не удалось определить статус сервисов. Как исправить — /diag")
    missing = []
    for u in statuses:
        if not u.exists:
            missing.append(u.name)
            continue
        if u.approximate and u.active_state == "unknown":
            lines.append(f"⚪️ <b>{esc(u.name)}</b> — нельзя определить по процессам")
            continue
        icon = "🟢" if u.ok else ("🔴" if u.active_state == "failed" else "🟡")
        detail = esc(u.description) if u.approximate else f"{esc(u.active_state)} ({esc(u.sub_state)})"
        lines.append(f"{icon} <b>{esc(u.name)}</b> — {detail}")
        if source == "systemd" and agent.actions.allowed("sr", u.name) and (cb := agent.actions.callback("sr", u.name)):
            restart_buttons.append((f"🔁 {u.name}", cb))
    if missing:
        lines.append("")
        for name in missing:
            pkg = INSTALL_HINTS.get(name)
            hint = f": <code>sudo apt install {pkg}</code>" if pkg else ""
            lines.append(f"⚪️ {esc(name)} — не установлен{hint}")
        lines.append("<i>Бот не устанавливает пакеты — это изменение системы вне списка разрешённых действий. "
                     "Установите вручную или уберите сервис из [services].units.</i>")
    if not units:
        lines.append("Список [services].units пуст.")
    failed = [f for f in agent.service_probe.failed_units() if f not in units]
    if failed:
        lines.append("\n<b>Юниты в состоянии failed:</b>")
        lines.extend(f"🔴 {esc(f)}" for f in failed[:20])
    for i in range(0, len(restart_buttons), 2):
        rows.append(restart_buttons[i:i + 2])
    rows.append([("🔄 Обновить", "v:services"), *BACK])
    return "\n".join(lines), rows


# --- ssh / security ---------------------------------------------------------------------


def ssh_view(agent: "Agent") -> View:
    rows: Rows = [[("🔄 Обновить", "v:ssh"), ("🛡 Безопасность", "v:security")], BACK]
    if agent.ssh is None:
        return "🔑 Мониторинг SSH выключен в конфигурации.", rows
    since = time.time() - 86400
    lines = [f"🔑 <b>SSH</b> (источник: {esc(agent.ssh.source_name or '—')})"]
    if agent.ssh.source_error:
        lines.append(f"❌ Ошибка чтения логов: <code>{esc(agent.ssh.source_error)}</code> — /diag")
    lines += ["", "<b>Последние входы:</b>"]
    logins = agent.storage.recent_ssh_logins(10)
    if not logins:
        lines.append("— пока нет записей")
    for r in logins:
        lines.append(f"• {fmt_ts(r.ts)} <b>{esc(r.user)}</b> с <code>{esc(r.ip)}</code> ({esc(r.method)})")
    total = agent.storage.ssh_failure_total(since)
    lines.append(f"\n<b>Неудачные попытки за 24ч:</b> {total}")
    for s in agent.storage.ssh_failure_stats(since, 7):
        lines.append(f"• <code>{esc(s['ip'])}</code> — {s['cnt']} (польз.: {s['users']}, посл. {fmt_ts(s['last_ts'], False)})")
    return "\n".join(lines), rows


def security_view(agent: "Agent") -> View:
    since = time.time() - 86400
    lines = ["🛡 <b>Безопасность за 24 часа</b>", ""]
    # SSH
    if agent.ssh is not None:
        logins = [r for r in agent.storage.recent_ssh_logins(50) if r.ts >= since]
        failures = agent.storage.ssh_failure_total(since)
        lines.append(f"🔑 <b>SSH:</b> входов {len(logins)}, неудачных попыток {failures}")
        for s in agent.storage.ssh_failure_stats(since, 3):
            lines.append(f"   • <code>{esc(s['ip'])}</code> — {s['cnt']} попыток")
    else:
        lines.append("🔑 SSH: мониторинг выключен")
    # firewall
    lines.append("")
    if agent.firewall is not None:
        st = agent.firewall.stats(since)
        if st["total"]:
            lines.append(f"🧱 <b>Файрвол:</b> заблокировано {st['total']} пакетов с {st['ips']} IP"
                         + (" (показаны последние 20 000)" if st["truncated"] else ""))
            for ip, cnt, nports, last in st["top_ips"][:5]:
                lines.append(f"   • <code>{esc(ip)}</code> — {cnt}, портов: {nports}, посл. {fmt_ts(last, False)}")
            if st["top_ports"]:
                lines.append("   Чаще всего стучались в: " + ", ".join(f"{port_label(p)}×{n}" for p, n in st["top_ports"][:5]))
        else:
            lines.append("🧱 <b>Файрвол:</b> блокировок не зафиксировано. Если файрвол включён, включите логирование: "
                         "<code>sudo ufw logging low</code>")
    else:
        lines.append("🧱 Файрвол: анализ выключен")
    # inbound connections
    lines.append("")
    if agent.connections is not None:
        recent = [x for x in agent.connections.last_inbound if x[0] >= since]
        lines.append(f"🔌 <b>Внешние подключения к опасным портам:</b> {len(recent)}")
        for ts, ip, port in recent[:5]:
            lines.append(f"   • {fmt_ts(ts, False)} <code>{esc(ip)}</code> → {port_label(port)}")
        if agent.connections.listening:
            lines.append("   Открыты: " + ", ".join(port_label(p) for p in sorted(agent.connections.listening)))
    # LAN
    if agent.lan is not None:
        untrusted = [d for d in agent.storage.list_devices() if not d.trusted]
        new = [d for d in untrusted if d.first_seen >= since]
        lines.append(f"\n📡 <b>LAN:</b> неизвестных устройств {len(untrusted)}, новых за сутки {len(new)}")
    alerts = [e for e in agent.storage.recent_events(50, "warning") if e.category == "security" and e.ts >= since]
    if alerts:
        lines.append("\n<b>Тревоги:</b>")
        for e in alerts[:7]:
            lines.append(f"{SEVERITY_ICON.get(e.severity, '')} {fmt_ts(e.ts, False)} {esc(e.title)}"
                         + (f" — <code>{esc(e.data.get('ip'))}</code>" if e.data.get("ip") else ""))
    rows: Rows = [[("🔄 Обновить", "v:security"), ("🔑 SSH", "v:ssh")], [("📡 Устройства", "v:devices"), *BACK]]
    return "\n".join(lines), rows


# --- events / devices / notify ------------------------------------------------------------


def events_view(agent: "Agent", show_all: bool = False) -> View:
    events = agent.storage.recent_events(20, None if show_all else "warning")
    title = "Все события" if show_all else "Важные события"
    lines = [f"📜 <b>{title}</b> (последние {len(events)})\n"]
    if not events:
        lines.append("Событий нет.")
    for e in events:
        lines.append(f"{SEVERITY_ICON.get(e.severity, '')} {fmt_ts(e.ts)} {esc(e.title)}")
    toggle = ("Только важные", "v:events") if show_all else ("Показать все", "v:events_all")
    return "\n".join(lines), [[toggle, ("🔄 Обновить", "v:events_all" if show_all else "v:events")], BACK]


def devices_view(agent: "Agent") -> View:
    rows: Rows = []
    if agent.lan is None:
        return "📡 Обнаружение устройств выключено в конфигурации.", [BACK]
    devices = agent.storage.list_devices()
    lines = [f"📡 <b>Устройства в LAN</b> ({len(devices)})"]
    if agent.lan.disabled_reason:
        lines.append(f"❌ Сканирование не работает: {esc(agent.lan.disabled_reason)}")
    if agent.lan.last_subnets:
        lines.append("Подсети: " + ", ".join(f"<code>{esc(s)}</code>" for s in agent.lan.last_subnets))
    if agent.lan.last_scan:
        lines.append(f"Последнее сканирование: {_ago(agent.lan.last_scan)}")
    lines.append("")
    untrusted = []
    for d in devices[:50]:
        icon = "✅" if d.trusted else "❓"
        name = d.name or d.hostname
        extra = " 🎲" if is_random_mac(d.mac) else ""
        lines.append(f"{icon} <code>{esc(d.ip)}</code> {esc(d.mac)}{extra}" + (f" — {esc(name)}" if name else "")
                     + f"\n    в сети: {_ago(d.last_seen)}")
        if not d.trusted:
            untrusted.append(d)
    if len(devices) > 50:
        lines.append(f"… и ещё {len(devices) - 50}")
    if not devices:
        lines.append("Пока ничего не найдено.")
    lines.append("\n✅ — доверенное, ❓ — неизвестное, 🎲 — случайный MAC")
    for d in untrusted[:6]:
        rows.append([(f"✅ {d.ip}", f"devv:trust:{d.mac}"), (f"🗑 {d.ip}", f"devv:forget:{d.mac}")])
    if untrusted:
        rows.append([("✅ Доверять всем", "devv:trustall")])
    rows.append([("🔎 Сканировать", "lan:scan"), ("🔄 Обновить", "v:devices")])
    rows.append([("🗑 Забыть все", "devv:forgetall"), *BACK])
    return "\n".join(lines), rows


def notify_view(agent: "Agent") -> View:
    s = agent.settings
    lines = ["🔔 <b>Уведомления</b>\n"]
    if s.is_muted():
        lines.append(f"🔕 Выключены до {fmt_ts(s.mute_until)}"
                     + (" (критические всё равно приходят)" if agent.cfg.notifications.mute_allows_critical else ""))
    else:
        lines.append("🔔 Включены")
    lines.append(f"Минимальная важность: <b>{esc(agent.cfg.notifications.min_severity)}</b> (меняется в конфиге)")
    lines.append("\nКатегории (нажмите, чтобы переключить; критические приходят всегда):")
    disabled = s.disabled_categories
    rows: Rows = [[("🔕 1 час", "mute:60"), ("🔕 8 часов", "mute:480"), ("🔕 24 часа", "mute:1440")]]
    if s.is_muted():
        rows.append([("🔔 Включить сейчас", "unmute")])
    cat_buttons = [(("✅ " if c not in disabled else "🔕 ") + title, f"cat:{c}") for c, title in CATEGORIES.items()]
    for i in range(0, len(cat_buttons), 2):
        rows.append(cat_buttons[i:i + 2])
    rows.append(BACK)
    return "\n".join(lines), rows


# --- actions / diagnostics ---------------------------------------------------------------


def actions_view(agent: "Agent") -> View:
    a = agent.actions
    lines = ["🛠 <b>Действия</b>", ""]
    if not a.enabled:
        lines.append("Действия отключены в конфигурации ([telegram].allow_actions = false).")
        return "\n".join(lines), [BACK]
    rows: Rows = []
    lines.append("Все действия требуют подтверждения и записываются в журнал.\n")
    if agent.docker is not None and a.container_patterns:
        pats = ", ".join(a.container_patterns)
        lines.append(f"🐳 <b>Контейнеры</b> ({esc(pats)}): перезапуск, запуск"
                     + (", остановка" if a.cfg.container_stop else "") + (", логи" if a.cfg.container_logs else "")
                     + " — выберите контейнер в списке.")
        rows.append([("🐳 Контейнеры", "v:docker")])
    if a.services:
        lines.append("⚙️ <b>Сервисы</b>: перезапуск — " + ", ".join(esc(s) for s in a.services))
        buttons = [(f"🔁 {u}", cb) for u in a.services if (cb := a.callback("sr", u))]
        for i in range(0, len(buttons), 2):
            rows.append(buttons[i:i + 2])
    else:
        lines.append("⚙️ Сервисы: перезапуск не разрешён ([actions].services пуст).")
    other: list[tuple[str, str]] = []
    if a.allowed("dp"):
        lines.append("🧹 <b>Очистка Docker</b>: удалить образы без тегов и кэш сборки.")
        other.append(("🧹 Очистить Docker", "a:dp:"))
    if a.allowed("ar"):
        lines.append("🔁 <b>Перезапуск агента</b>: например, после правки config.toml.")
        other.append(("🔁 Перезапустить агент", "a:ar:"))
    if other:
        rows.append(other)
    lines.append("\nБез подтверждения: 🔍 проверить всё сейчас, 🔎 просканировать LAN.")
    rows.append([("🔍 Проверить всё", "chk"), ("🔎 Сканировать LAN", "lan:scan")])
    rows.append(BACK)
    return "\n".join(lines), rows


def diag_view(agent: "Agent") -> View:
    checks = diagnostics.collect(agent)
    fails = sum(1 for c in checks if c.level == "fail")
    warns = sum(1 for c in checks if c.level == "warn")
    head = "🩺 <b>Диагностика</b>\n" + ("Всё настроено ✅" if not fails and not warns else
                                        f"Проблем: {fails}, предупреждений: {warns}")
    body = "\n\n".join(c.render() for c in checks)
    return f"{head}\n\n{body}", [[("🔄 Обновить", "v:diag"), *BACK]]


def about_text(agent: "Agent") -> str:
    return (f"Shelter Monitor Agent {__version__} на <code>{esc(agent.host)}</code>\n"
            f"Агент работает {fmt_duration(time.time() - agent.started_at)}")
