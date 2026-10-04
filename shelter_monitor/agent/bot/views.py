"""Telegram screens. Each view returns (html_text, inline_keyboard_rows)."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from shelter_monitor import __version__
from shelter_monitor.agent.collectors.docker import DockerError
from shelter_monitor.agent.events import CATEGORIES
from shelter_monitor.agent.lan import is_random_mac
from shelter_monitor.agent.notifier import SEVERITY_ICON
from shelter_monitor.util import bar, esc, fmt_bytes, fmt_duration, fmt_rate, fmt_ts

if TYPE_CHECKING:  # pragma: no cover
    from shelter_monitor.agent.app import Agent

Rows = list[list[tuple[str, str]]]
View = tuple[str, Rows]

MAIN_MENU: Rows = [
    [("🔄 Обновить", "v:status"), ("📊 Метрики", "v:metrics")],
    [("🐳 Docker", "v:docker"), ("⚙️ Сервисы", "v:services")],
    [("🔑 SSH", "v:ssh"), ("📜 События", "v:events")],
    [("📡 Устройства LAN", "v:devices"), ("🔔 Уведомления", "v:notify")],
    [("🛠 Действия", "v:actions"), ("✅ Проверить сейчас", "chk")],
]

BACK: list[tuple[str, str]] = [("⬅️ Меню", "v:status")]

HELP_TEXT = """<b>Shelter Monitor Agent</b> — мониторинг сервера

/status — сводка и активные проблемы
/metrics — CPU, память, диски, сеть, температура
/docker — контейнеры Docker
/services — сервисы systemd
/ssh — SSH-входы и неудачные попытки
/events — последние события
/devices — устройства в локальной сети
/check — запустить все проверки сейчас
/notify — настройки уведомлений
/mute [30m|2h|1d] — выключить уведомления на время
/unmute — включить уведомления
/actions — разрешённые действия (перезапуск сервисов/контейнеров)
/id — ваш Telegram ID и ID чата

Бот не выполняет произвольные команды: доступны только действия из списка, заданного в конфигурации сервера, и каждое требует подтверждения."""


def _ago(ts: float) -> str:
    return fmt_duration(time.time() - ts) + " назад"


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
    if agent.services_units:
        statuses = [u for u in agent.systemd.status(agent.services_units) if u.exists] if agent.systemd.available() else []
        if statuses:
            ok = sum(1 for u in statuses if u.ok)
            lines.append(f"⚙️ Сервисы: {ok}/{len(statuses)} активны")

    logins = agent.storage.recent_ssh_logins(1)
    failures = agent.storage.ssh_failure_total(time.time() - 86400)
    if logins:
        last = logins[0]
        lines.append(f"🔑 Последний SSH-вход: {esc(last.user)} с <code>{esc(last.ip)}</code> ({fmt_ts(last.ts)})")
    if failures:
        lines.append(f"🚫 Неудачных SSH-попыток за 24ч: {failures}")

    if agent.heartbeat is not None:
        hb = agent.heartbeat
        if hb.last_ok:
            lines.append(f"💓 Heartbeat: OK, {_ago(hb.last_ok)}")
        elif hb.last_error:
            lines.append(f"💔 Heartbeat: ошибка — {esc(hb.last_error)[:100]}")
    if agent.settings.is_muted():
        lines.append(f"🔕 Уведомления выключены до {fmt_ts(agent.settings.mute_until)}")
    return "\n".join(lines), MAIN_MENU


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
    return "\n".join(lines), [[("🔄 Обновить", "v:metrics"), *BACK]]


def docker_view(agent: "Agent") -> View:
    rows: Rows = [[("🔄 Обновить", "v:docker"), *BACK]]
    if agent.docker is None:
        return "🐳 Мониторинг Docker выключен в конфигурации.", rows
    if not agent.docker.available():
        return f"🐳 Docker не найден (нет сокета <code>{esc(agent.docker.socket_path)}</code>).", rows
    try:
        containers = agent.docker.containers()
    except DockerError as exc:
        return f"🐳 Docker недоступен: {esc(exc)}", rows
    if not containers:
        return "🐳 Контейнеров нет.", rows
    running = sum(1 for c in containers if c.state == "running")
    lines = [f"🐳 <b>Docker</b>: {running}/{len(containers)} запущено\n"]
    for c in containers[:60]:
        if c.state == "running":
            icon = "⚠️" if c.health == "unhealthy" else "🟢"
        elif c.state in ("restarting", "paused", "created"):
            icon = "🟡"
        else:
            icon = "🔴"
        lines.append(f"{icon} <b>{esc(c.name)}</b> — {esc(c.status)}\n    <code>{esc(c.image[:60])}</code>")
    if len(containers) > 60:
        lines.append(f"… и ещё {len(containers) - 60}")
    if agent.actions.containers:
        rows.insert(0, [("🛠 Перезапуск контейнеров", "v:actions")])
    return "\n".join(lines), rows


def services_view(agent: "Agent") -> View:
    rows: Rows = [[("🔄 Обновить", "v:services"), *BACK]]
    if not agent.systemd.available():
        return "⚙️ systemd не обнаружен.", rows
    units = agent.services_units or []
    lines = ["⚙️ <b>Сервисы</b>\n"]
    for u in agent.systemd.status(units):
        if not u.exists:
            lines.append(f"⚪️ {esc(u.name)} — не установлен")
            continue
        icon = "🟢" if u.ok else ("🔴" if u.active_state == "failed" else "🟡")
        lines.append(f"{icon} <b>{esc(u.name)}</b> — {esc(u.active_state)} ({esc(u.sub_state)})")
    if not units:
        lines.append("Список [services].units пуст.")
    failed = [f for f in agent.systemd.failed_units() if f not in units]
    if failed:
        lines.append("\n<b>Юниты в состоянии failed:</b>")
        lines.extend(f"🔴 {esc(f)}" for f in failed[:20])
    if agent.actions.services:
        rows.insert(0, [("🛠 Перезапуск сервисов", "v:actions")])
    return "\n".join(lines), rows


def ssh_view(agent: "Agent") -> View:
    rows: Rows = [[("🔄 Обновить", "v:ssh"), *BACK]]
    if agent.ssh is None:
        return "🔑 Мониторинг SSH выключен в конфигурации.", rows
    since = time.time() - 86400
    lines = [f"🔑 <b>SSH</b> (источник: {esc(agent.ssh.source_name or '—')})\n", "<b>Последние входы:</b>"]
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
    if agent.lan.last_subnets:
        lines.append("Подсети: " + ", ".join(f"<code>{esc(s)}</code>" for s in agent.lan.last_subnets))
    if agent.lan.last_scan:
        lines.append(f"Последнее сканирование: {_ago(agent.lan.last_scan)}")
    lines.append("")
    untrusted = []
    for d in devices[:60]:
        icon = "✅" if d.trusted else "❓"
        name = d.name or d.hostname
        extra = " 🎲" if is_random_mac(d.mac) else ""
        lines.append(f"{icon} <code>{esc(d.ip)}</code> {esc(d.mac)}{extra}" + (f" — {esc(name)}" if name else "")
                     + f"\n    в сети: {_ago(d.last_seen)}")
        if not d.trusted:
            untrusted.append(d)
    if not devices:
        lines.append("Пока ничего не найдено — первое сканирование выполняется в фоне.")
    lines.append("\n✅ — доверенное, ❓ — неизвестное, 🎲 — случайный MAC")
    for d in untrusted[:8]:
        rows.append([(f"✅ Доверять {d.ip}", f"dev:trust:{d.mac}")])
    rows.append([("🔎 Сканировать", "lan:scan"), ("🔄 Обновить", "v:devices")])
    rows.append(BACK)
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


def actions_view(agent: "Agent") -> View:
    a = agent.actions
    lines = ["🛠 <b>Действия</b>\n"]
    rows: Rows = []
    if not a.enabled:
        lines.append("Действия отключены в конфигурации.")
        return "\n".join(lines), [BACK]
    if not a.services and not a.containers:
        lines.append("Список разрешённых действий пуст.\nДобавьте сервисы и контейнеры в секцию <code>[actions]</code> "
                     "конфигурационного файла на сервере.")
        return "\n".join(lines), [BACK]
    lines.append("Выберите объект для перезапуска. Действие потребует подтверждения.")
    for i, unit in enumerate(a.services):
        rows.append([(f"🔁 сервис {unit}", f"act:s:{i}")])
    for i, name in enumerate(a.containers):
        rows.append([(f"🔁 контейнер {name}", f"act:c:{i}")])
    rows.append(BACK)
    return "\n".join(lines), rows


def about_text(agent: "Agent") -> str:
    return (f"Shelter Monitor Agent {__version__} на <code>{esc(agent.host)}</code>\n"
            f"Агент работает {fmt_duration(time.time() - agent.started_at)}")


