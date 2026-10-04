"""Small shared helpers: formatting, escaping, logging setup, TOML loading."""

from __future__ import annotations

import html
import logging
import sys
import time
from typing import Any

try:  # Python 3.11+
    import tomllib as _toml
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 (Ubuntu 22.04): apt install python3-tomli
    try:
        import tomli as _toml  # type: ignore[no-redef]
    except ModuleNotFoundError:
        _toml = None  # type: ignore[assignment]


def load_toml(path: str) -> dict[str, Any]:
    if _toml is None:
        raise RuntimeError(
            "TOML parser not available: use Python 3.11+ or install python3-tomli (apt install python3-tomli)"
        )
    with open(path, "rb") as fh:
        return _toml.load(fh)


def esc(value: Any) -> str:
    """Escape a value for Telegram HTML parse mode."""
    return html.escape(str(value), quote=False)


def fmt_bytes(num: float) -> str:
    step = 1024.0
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(num) < step:
            return f"{num:.0f} {unit}" if unit == "B" else f"{num:.1f} {unit}"
        num /= step
    return f"{num:.1f} PiB"


def fmt_rate(bytes_per_sec: float) -> str:
    return fmt_bytes(bytes_per_sec) + "/s"


def fmt_duration(seconds: float) -> str:
    seconds = int(max(0, seconds))
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    if days:
        return f"{days}д {hours}ч {minutes}м"
    if hours:
        return f"{hours}ч {minutes}м"
    if minutes:
        return f"{minutes}м {secs}с"
    return f"{secs}с"


def fmt_ts(ts: float, with_date: bool = True) -> str:
    fmt = "%d.%m %H:%M:%S" if with_date else "%H:%M:%S"
    return time.strftime(fmt, time.localtime(ts))


def bar(percent: float, width: int = 10) -> str:
    percent = max(0.0, min(100.0, percent))
    filled = int(round(percent / 100 * width))
    return "█" * filled + "░" * (width - filled)


def setup_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stderr)
    # systemd/journald adds its own timestamps; keep the format compact.
    handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
