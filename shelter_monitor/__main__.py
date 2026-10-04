"""Entry point: ``python3 -m shelter_monitor {agent|watchdog} ...``."""

from __future__ import annotations

import sys


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help"):
        print("usage: python3 -m shelter_monitor {agent|watchdog} <command> [options]")
        return 0 if argv else 2
    component, rest = argv[0], argv[1:]
    if component == "agent":
        from shelter_monitor.agent.cli import main as agent_main

        return agent_main(rest)
    if component == "watchdog":
        from shelter_monitor.watchdog.cli import main as watchdog_main

        return watchdog_main(rest)
    if component in ("-V", "--version", "version"):
        from shelter_monitor import __version__

        print(__version__)
        return 0
    print(f"unknown component: {component!r} (expected 'agent' or 'watchdog')", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
