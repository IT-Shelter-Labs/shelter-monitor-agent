"""`shelter-watchdog` command line interface."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import signal
import sys
import threading
from typing import Any

from shelter_monitor import __version__
from shelter_monitor.util import setup_logging
from shelter_monitor.watchdog import config as config_mod


def _load(path: str) -> config_mod.WatchdogConfig:
    try:
        return config_mod.load(path)
    except config_mod.ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(2)


def cmd_run(args: argparse.Namespace) -> int:
    cfg = _load(args.config)
    setup_logging(cfg.log_level)
    from shelter_monitor.telegram import Outbox, TelegramAPI
    from shelter_monitor.watchdog.server import Watchdog, WatchdogServer

    outbox = Outbox(TelegramAPI(cfg.telegram_token, cfg.telegram_api_url, cfg.telegram_proxy), max_attempts=30)
    outbox.start()

    def notify(text: str) -> None:
        for chat in cfg.chat_ids:
            outbox.send(chat, text)

    server = WatchdogServer(Watchdog(cfg, notify))

    def on_signal(_signum: int, _frame: Any) -> None:
        # httpd.shutdown() blocks until serve_forever exits, so it can't run in the main thread.
        threading.Thread(target=server.request_stop, daemon=True).start()

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)
    try:
        server.serve_forever()
    finally:
        server.close()
        outbox.stop()
    return 0


def cmd_check_config(args: argparse.Namespace) -> int:
    cfg = _load(args.config)
    if args.quiet:
        return 0
    print(json.dumps({"listen": f"{cfg.listen}:{cfg.port}", "agents": [a.id for a in cfg.agents],
                      "chat_ids": cfg.chat_ids}, indent=2))
    print("configuration OK", file=sys.stderr)
    return 0


def cmd_gen_token(_args: argparse.Namespace) -> int:
    print(secrets.token_hex(32))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="shelter-watchdog", description="Shelter Watchdog (heartbeat receiver)")
    parser.add_argument("-V", "--version", action="version", version=__version__)
    parser.add_argument("-c", "--config", default=os.environ.get("SHELTER_WATCHDOG_CONFIG", config_mod.DEFAULT_CONFIG_PATH))
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("run", help="run the watchdog server").set_defaults(func=cmd_run)
    p = sub.add_parser("check-config", help="validate the config file")
    p.add_argument("-q", "--quiet", action="store_true", help="only validate, print nothing on success")
    p.set_defaults(func=cmd_check_config)
    sub.add_parser("gen-token", help="generate a random agent token").set_defaults(func=cmd_gen_token)
    args = parser.parse_args(argv)
    return args.func(args)
