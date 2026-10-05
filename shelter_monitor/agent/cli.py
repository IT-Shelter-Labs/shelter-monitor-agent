"""`shelter-agent` command line interface."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

from shelter_monitor import __version__
from shelter_monitor.agent import config as config_mod
from shelter_monitor.util import fmt_bytes, fmt_duration, setup_logging


def _load(path: str) -> config_mod.Config:
    try:
        cfg = config_mod.load(path)
    except config_mod.ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(2)
    for warning in cfg.warnings:
        print(f"warning: {warning}", file=sys.stderr)
    return cfg


def cmd_run(args: argparse.Namespace) -> int:
    cfg = _load(args.config)
    setup_logging(args.log_level or cfg.agent.log_level)
    from shelter_monitor.agent.app import Agent

    try:
        os.makedirs(cfg.agent.data_dir, exist_ok=True)
        agent = Agent(cfg)
    except OSError as exc:
        print(f"error: cannot use data_dir {cfg.agent.data_dir}: {exc}", file=sys.stderr)
        return 1
    agent.run_forever()
    return 0


def cmd_check_config(args: argparse.Namespace) -> int:
    cfg = _load(args.config)
    if not args.quiet:
        print(json.dumps(config_mod.as_dict(cfg), indent=2, ensure_ascii=False))
        print("\nconfiguration OK", file=sys.stderr)
    return 0


def cmd_test_telegram(args: argparse.Namespace) -> int:
    cfg = _load(args.config)
    from shelter_monitor.telegram import TelegramAPI, TelegramError

    api = TelegramAPI(cfg.telegram.token, cfg.telegram.api_url, cfg.telegram.proxy)
    try:
        me = api.get_me()
        print(f"bot: @{me.get('username')} (id {me.get('id')})")
        for chat in cfg.notify_chats:
            api.send_message(chat, f"✅ Тестовое сообщение от Shelter Monitor Agent (<code>{cfg.host_name}</code>)")
            print(f"sent test message to {chat}")
    except TelegramError as exc:
        print(f"error: {exc}", file=sys.stderr)
        if "chat not found" in str(exc).lower():
            print("hint: open the bot in Telegram and press Start first", file=sys.stderr)
        return 1
    return 0


def cmd_get_chat_id(args: argparse.Namespace) -> int:
    """Print ids of users who message the bot. Works before admin_ids is configured."""
    from shelter_monitor.telegram import TelegramAPI, TelegramError

    token = args.token or os.environ.get("SHELTER_TELEGRAM_TOKEN", "")
    if not token:
        try:
            raw = config_mod.load_toml(args.config)
            token = raw.get("telegram", {}).get("token", "")
            if not token and raw.get("telegram", {}).get("token_file"):
                with open(raw["telegram"]["token_file"], encoding="utf-8") as fh:
                    token = fh.read().strip()
        except (OSError, ValueError):
            pass
    if not token:
        print("error: pass --token or set [telegram].token in the config", file=sys.stderr)
        return 2
    api = TelegramAPI(token)
    print("Send any message to the bot in Telegram (Ctrl+C to stop)...")
    offset = None
    seen = set()
    deadline = time.time() + args.wait
    try:
        while time.time() < deadline:
            try:
                updates = api.get_updates(offset, timeout=20)
            except TelegramError as exc:
                print(f"error: {exc}", file=sys.stderr)
                if exc.code == 409:
                    print("hint: stop the running agent first: systemctl stop shelter-agent", file=sys.stderr)
                return 1
            for upd in updates:
                offset = upd["update_id"] + 1
                msg = upd.get("message") or {}
                user = msg.get("from") or {}
                chat = msg.get("chat") or {}
                key = (user.get("id"), chat.get("id"))
                if key not in seen and user:
                    seen.add(key)
                    print(f"user id: {user.get('id')}  (@{user.get('username', '-')}, {user.get('first_name', '')})"
                          f"  chat id: {chat.get('id')} [{chat.get('type')}]")
    except KeyboardInterrupt:
        pass
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    from shelter_monitor.agent.collectors.system import CpuSampler, NetSampler, SystemCollector, take_snapshot

    col = SystemCollector(host_root=os.environ.get("SHELTER_HOST_ROOT", ""))
    snap = take_snapshot(col, CpuSampler(col), NetSampler(col))
    if args.json:
        print(json.dumps(snap.to_dict(), indent=2, default=str))
        return 0
    print(f"{snap.hostname} — {snap.os_name}, kernel {snap.kernel}, up {fmt_duration(snap.uptime)}")
    print(f"CPU {snap.cpu_percent:.1f}% ({snap.cpu_count} cores), load {snap.load[0]:.2f} {snap.load[1]:.2f} {snap.load[2]:.2f}")
    m = snap.memory
    print(f"RAM {m.percent:.1f}% ({fmt_bytes(m.used)} / {fmt_bytes(m.total)}), swap {m.swap_percent:.1f}%")
    for d in snap.disks:
        print(f"disk {d.mount}: {d.percent:.1f}% ({fmt_bytes(d.free)} free of {fmt_bytes(d.total)})")
    if snap.temperature is not None:
        print(f"temperature {snap.temperature}°C")
    return 0


def cmd_healthcheck(args: argparse.Namespace) -> int:
    """Exit 0 if the running agent refreshed its liveness marker recently (Docker HEALTHCHECK)."""
    data_dir = config_mod.AgentSection().data_dir
    try:
        data_dir = config_mod.load(args.config).agent.data_dir
    except config_mod.ConfigError:
        pass
    path = os.path.join(data_dir, "health")
    try:
        age = time.time() - os.path.getmtime(path)
    except OSError:
        print(f"unhealthy: {path} not found", file=sys.stderr)
        return 1
    if age > args.max_age:
        print(f"unhealthy: last liveness mark {age:.0f}s ago", file=sys.stderr)
        return 1
    print(f"healthy ({age:.0f}s ago)")
    return 0


def cmd_sudoers(args: argparse.Namespace) -> int:
    cfg = _load(args.config)
    from shelter_monitor.agent.actions import ActionManager

    manager = ActionManager(cfg.actions, bus=None, docker=None)  # type: ignore[arg-type]
    sys.stdout.write(manager.sudoers_rules(args.user))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="shelter-agent", description="Shelter Monitor Agent")
    parser.add_argument("-V", "--version", action="version", version=__version__)
    parser.add_argument("-c", "--config", default=os.environ.get("SHELTER_AGENT_CONFIG", config_mod.DEFAULT_CONFIG_PATH))
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("run", help="run the agent (used by systemd)")
    p.add_argument("--log-level", default="")
    p.set_defaults(func=cmd_run)
    p = sub.add_parser("check-config", help="validate the config file")
    p.add_argument("-q", "--quiet", action="store_true", help="only validate, print nothing on success")
    p.set_defaults(func=cmd_check_config)
    sub.add_parser("test-telegram", help="send a test message").set_defaults(func=cmd_test_telegram)
    p = sub.add_parser("get-chat-id", help="show Telegram user/chat ids of people messaging the bot")
    p.add_argument("--token", default="")
    p.add_argument("--wait", type=int, default=120, help="seconds to wait (default 120)")
    p.set_defaults(func=cmd_get_chat_id)
    p = sub.add_parser("status", help="print current system metrics")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_status)
    p = sub.add_parser("healthcheck", help="check that the running agent is alive (for Docker)")
    p.add_argument("--max-age", type=int, default=180)
    p.set_defaults(func=cmd_healthcheck)
    p = sub.add_parser("sudoers", help="print sudoers rules for allowlisted service restarts")
    p.add_argument("--user", default="shelter")
    p.set_defaults(func=cmd_sudoers)

    args = parser.parse_args(argv)
    return args.func(args)
