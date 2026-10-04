"""Agent configuration: TOML file -> typed dataclasses with validation."""

from __future__ import annotations

import dataclasses
import ipaddress
import os
import re
import socket
from dataclasses import dataclass, field
from typing import Any, get_type_hints

from shelter_monitor.util import load_toml

DEFAULT_CONFIG_PATH = "/etc/shelter-agent/config.toml"

# Names that may appear in allowlists. Strict on purpose: these values end up as
# arguments to systemctl / Docker API paths.
UNIT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9@_.\-]{0,127}$")
CONTAINER_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,127}$")

SEVERITIES = ("info", "warning", "critical")


class ConfigError(Exception):
    pass


@dataclass
class AgentSection:
    name: str = ""
    data_dir: str = "/var/lib/shelter-agent"
    log_level: str = "INFO"
    retention_days: int = 30


@dataclass
class TelegramSection:
    token: str = ""
    token_file: str = ""
    api_url: str = "https://api.telegram.org"
    proxy: str = ""
    admin_ids: list[int] = field(default_factory=list)
    notify_chat_ids: list[int] = field(default_factory=list)
    allow_actions: bool = True


@dataclass
class NotificationsSection:
    min_severity: str = "warning"
    mute_allows_critical: bool = True
    silent_info: bool = True


@dataclass
class MonitorSection:
    interval: int = 30
    cpu_percent: float = 90.0
    cpu_sustain: int = 5
    memory_percent: float = 90.0
    swap_percent: float = 80.0
    disk_percent: float = 85.0
    disk_critical_percent: float = 95.0
    load_per_cpu: float = 2.0
    temperature_c: float = 85.0
    disk_mounts: list[str] = field(default_factory=list)
    disk_ignore: list[str] = field(default_factory=lambda: ["/boot/efi", "/snap/*", "/var/lib/docker/*"])
    net_interfaces: list[str] = field(default_factory=list)


@dataclass
class DockerSection:
    enabled: bool = True
    socket: str = "/var/run/docker.sock"
    interval: int = 30
    watch: list[str] = field(default_factory=list)
    ignore: list[str] = field(default_factory=list)
    alert_on_unhealthy: bool = True


@dataclass
class ServicesSection:
    enabled: bool = True
    interval: int = 60
    units: list[str] = field(default_factory=lambda: ["ssh", "cron", "docker"])
    watch_failed_units: bool = True


@dataclass
class ConnectivitySection:
    enabled: bool = True
    interval: int = 60
    targets: list[str] = field(default_factory=lambda: ["1.1.1.1:53", "8.8.8.8:53"])
    failures_before_alert: int = 3


@dataclass
class SSHSection:
    enabled: bool = True
    source: str = "auto"
    log_file: str = "/var/log/auth.log"
    notify_success: bool = True
    bruteforce_threshold: int = 10
    bruteforce_window: int = 300
    bruteforce_cooldown: int = 3600
    trusted_networks: list[str] = field(default_factory=list)


@dataclass
class LANSection:
    enabled: bool = True
    interval: int = 300
    subnets: list[str] = field(default_factory=list)
    active_probe: bool = True
    max_hosts: int = 1024
    baseline_first_scan: bool = True


@dataclass
class HeartbeatSection:
    enabled: bool = False
    url: str = ""
    token: str = ""
    interval: int = 60
    method: str = "POST"
    timeout: int = 10


@dataclass
class ActionsSection:
    services: list[str] = field(default_factory=list)
    containers: list[str] = field(default_factory=list)
    confirm_timeout: int = 60
    use_sudo: str = "auto"


@dataclass
class Config:
    agent: AgentSection = field(default_factory=AgentSection)
    telegram: TelegramSection = field(default_factory=TelegramSection)
    notifications: NotificationsSection = field(default_factory=NotificationsSection)
    monitor: MonitorSection = field(default_factory=MonitorSection)
    docker: DockerSection = field(default_factory=DockerSection)
    services: ServicesSection = field(default_factory=ServicesSection)
    connectivity: ConnectivitySection = field(default_factory=ConnectivitySection)
    ssh: SSHSection = field(default_factory=SSHSection)
    lan: LANSection = field(default_factory=LANSection)
    heartbeat: HeartbeatSection = field(default_factory=HeartbeatSection)
    actions: ActionsSection = field(default_factory=ActionsSection)
    path: str = ""
    warnings: list[str] = field(default_factory=list)

    @property
    def host_name(self) -> str:
        return self.agent.name or socket.gethostname()

    @property
    def notify_chats(self) -> list[int]:
        return self.telegram.notify_chat_ids or self.telegram.admin_ids


def _coerce(section: str, key: str, value: Any, typ: Any) -> Any:
    where = f"[{section}].{key}"
    if typ is bool:
        if not isinstance(value, bool):
            raise ConfigError(f"{where}: expected true/false")
        return value
    if typ is int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ConfigError(f"{where}: expected integer")
        return value
    if typ is float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ConfigError(f"{where}: expected number")
        return float(value)
    if typ is str:
        if not isinstance(value, str):
            raise ConfigError(f"{where}: expected string")
        return value
    if typ == list[str]:
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise ConfigError(f"{where}: expected list of strings")
        return list(value)
    if typ == list[int]:
        if not isinstance(value, list) or not all(isinstance(v, int) and not isinstance(v, bool) for v in value):
            raise ConfigError(f"{where}: expected list of integers")
        return list(value)
    raise ConfigError(f"{where}: unsupported type")  # pragma: no cover


def from_dict(raw: dict[str, Any], path: str = "") -> Config:
    cfg = Config(path=path)
    hints = get_type_hints(Config)
    for section_name, section_raw in raw.items():
        if section_name not in hints or section_name in ("path", "warnings"):
            cfg.warnings.append(f"unknown section [{section_name}] ignored")
            continue
        if not isinstance(section_raw, dict):
            raise ConfigError(f"[{section_name}] must be a table")
        section_obj = getattr(cfg, section_name)
        section_hints = get_type_hints(type(section_obj))
        for key, value in section_raw.items():
            if key not in section_hints:
                cfg.warnings.append(f"unknown option [{section_name}].{key} ignored")
                continue
            setattr(section_obj, key, _coerce(section_name, key, value, section_hints[key]))
    _finalize(cfg)
    return cfg


def load(path: str = DEFAULT_CONFIG_PATH) -> Config:
    if not os.path.exists(path):
        raise ConfigError(f"config file not found: {path}")
    try:
        raw = load_toml(path)
    except (ValueError, RuntimeError) as exc:  # TOMLDecodeError subclasses ValueError; RuntimeError: no parser
        raise ConfigError(f"{path}: {exc}") from None
    return from_dict(raw, path)


def _finalize(cfg: Config) -> None:
    errors: list[str] = []
    tg = cfg.telegram
    if tg.token_file and not tg.token:
        try:
            with open(tg.token_file, encoding="utf-8") as fh:
                tg.token = fh.read().strip()
        except OSError as exc:
            errors.append(f"[telegram].token_file: {exc}")
    env_token = os.environ.get("SHELTER_TELEGRAM_TOKEN")
    if env_token:
        tg.token = env_token.strip()
    if not tg.token:
        errors.append("[telegram].token (or token_file / SHELTER_TELEGRAM_TOKEN) is required")
    elif not re.match(r"^\d+:[A-Za-z0-9_-]{20,}$", tg.token):
        errors.append("[telegram].token does not look like a bot token (expected '123456:ABC...')")
    if not tg.admin_ids:
        errors.append("[telegram].admin_ids must contain at least one Telegram user id")

    if cfg.notifications.min_severity not in SEVERITIES:
        errors.append(f"[notifications].min_severity must be one of {', '.join(SEVERITIES)}")

    for sect_name in ("monitor", "docker", "services", "connectivity", "lan", "heartbeat"):
        if getattr(cfg, sect_name).interval < 5:
            errors.append(f"[{sect_name}].interval must be >= 5 seconds")

    if cfg.ssh.source not in ("auto", "journal", "file"):
        errors.append("[ssh].source must be auto, journal or file")
    for net in cfg.ssh.trusted_networks:
        try:
            ipaddress.ip_network(net, strict=False)
        except ValueError:
            errors.append(f"[ssh].trusted_networks: invalid network {net!r}")
    for net in cfg.lan.subnets:
        try:
            ipaddress.IPv4Network(net, strict=False)
        except ValueError:
            errors.append(f"[lan].subnets: invalid IPv4 network {net!r}")

    for target in cfg.connectivity.targets:
        host, _, port = target.rpartition(":")
        if not host or not port.isdigit():
            errors.append(f"[connectivity].targets: expected host:port, got {target!r}")

    hb = cfg.heartbeat
    if hb.enabled:
        if not hb.url.startswith(("http://", "https://")):
            errors.append("[heartbeat].url must be an http(s) URL when heartbeat is enabled")
        if hb.method.upper() not in ("GET", "POST"):
            errors.append("[heartbeat].method must be GET or POST")
        hb.method = hb.method.upper()
        if hb.url.startswith("http://"):
            cfg.warnings.append("[heartbeat].url uses plain http; prefer https so the token is not sent in clear text")

    act = cfg.actions
    for unit in act.services + cfg.services.units:
        if not UNIT_NAME_RE.match(unit):
            errors.append(f"invalid systemd unit name {unit!r}")
    for name in act.containers:
        if not CONTAINER_NAME_RE.match(name):
            errors.append(f"[actions].containers: invalid container name {name!r}")
    if act.use_sudo not in ("auto", "always", "never"):
        errors.append("[actions].use_sudo must be auto, always or never")
    if act.confirm_timeout < 10:
        errors.append("[actions].confirm_timeout must be >= 10 seconds")

    if errors:
        raise ConfigError("invalid configuration:\n  - " + "\n  - ".join(errors))


def normalize_unit(unit: str) -> str:
    """'nginx' -> 'nginx.service'; names with an explicit type suffix are kept."""
    if "." in unit and unit.rsplit(".", 1)[1] in (
        "service", "socket", "timer", "mount", "path", "target", "slice", "scope", "device", "swap", "automount"
    ):
        return unit
    return unit + ".service"


def as_dict(cfg: Config) -> dict[str, Any]:
    """Config as a dict with secrets masked (for `check-config` output)."""
    data = dataclasses.asdict(cfg)
    data["telegram"]["token"] = "***" if cfg.telegram.token else ""
    data["heartbeat"]["token"] = "***" if cfg.heartbeat.token else ""
    return data
