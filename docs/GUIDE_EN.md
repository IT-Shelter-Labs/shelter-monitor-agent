# Operations guide

[English overview](../README_EN.md) · [Русское руководство](GUIDE_RU.md)

## Architecture

One agent runs on the Linux host being monitored. Independent scheduled collectors read `/proc`, `/sys`, the Docker Unix socket, systemd, and SSH/firewall logs. Events go through an event bus into SQLite; notification filters and an in-memory outgoing queue deliver messages through the Telegram Bot API. The bot uses long polling, so the agent does not need a public inbound HTTP port.

The optional watchdog is a separate HTTP service on another machine. It receives heartbeats and reports missing agents. It is not a central web dashboard.

```text
Linux host -> collectors -> events -> SQLite
                               |
                          notifications -> Telegram bot
Linux host -> heartbeat -> external observer -> outage alert
```

The `shelter_monitor/agent/` package contains collectors, monitors, storage, the bot, diagnostics, and actions. `shelter_monitor/watchdog/` contains the heartbeat receiver. Runtime version: `shelter_monitor/__init__.py`.

## Native installation

See the [quick start](../README_EN.md#install-without-docker) first. The installer targets Debian/Ubuntu, installs missing Python dependencies through apt, creates a `shelter` system user, and installs code into `/opt/shelter-monitor`.

| Path | Purpose |
|---|---|
| `/etc/shelter-agent/config.toml` | Agent configuration, mode `0640 root:shelter` |
| `/var/lib/shelter-agent/agent.db` | Event history, SSH records, devices, preferences |
| `/usr/local/bin/shelter-agent` | CLI wrapper |
| `/etc/systemd/system/shelter-agent.service` | Agent service |
| `/etc/shelter-watchdog/config.toml` | Watchdog configuration, when installed |

Flags: `--agent` (default), `--watchdog`, `--no-start`, `--no-docker-group`. Existing configuration is preserved on upgrade. The native service uses the `adm` and `systemd-journal` groups for logs and optionally the `docker` group. Adding a group requires restarting the service.

For service restarts, generate and validate sudoers rules after configuring allowed units:

```bash
sudo shelter-agent sudoers | sudo tee /etc/sudoers.d/shelter-agent
sudo visudo -cf /etc/sudoers.d/shelter-agent
```

Review the generated file before enabling actions. After changing the allowed services, regenerate it. If service actions are unnecessary, disable them and consider a systemd override with `NoNewPrivileges=yes`.

## Docker deployment

Use the supplied [compose file](../docker-compose.yml) on the monitored Linux host. It builds the agent image locally from `python:3.13-slim` with systemd client tools. The same image can run watchdog.

| Setting | Purpose |
|---|---|
| `network_mode: host` | Host interfaces, network checks, ARP/LAN discovery |
| `/:/host:ro,rslave` | Host disk mounts, OS identity, access to host paths |
| `/var/run/docker.sock` | Container inspection and permitted Docker actions |
| `/run/systemd:ro` | Host systemd communication |
| `/var/log`, `/run/log/journal`, `/etc/machine-id` read-only | SSH/firewall logs and journal identity |
| `/etc/localtime:ro` | Host timezone |
| `shelter-data` | Persistent SQLite database and agent liveness records |

The container runs as root with dropped capabilities, `DAC_READ_SEARCH`, a read-only root filesystem, a temporary `/tmp`, `no-new-privileges`, and a 200 MB memory limit. Docker socket access still effectively grants host root privileges.

The client negotiates an API version between 1.41 and 1.44 using the daemon's unversioned `/version` endpoint before container requests. This covers Docker 20.10 and Docker 29, whose default minimum is 1.44. A non-overlapping range produces an error before an action is sent. See the [Docker API compatibility matrix](https://docs.docker.com/reference/api/engine/). Restart the agent after upgrading the Docker daemon to refresh the negotiated version.

For host service restarts, the compose file offers an optional `SYS_ADMIN` capability. It is disabled by default and is not needed merely to query service status. Service restarts from Docker do not use sudo. A read-only bind mount does not make Docker API actions read-only.

Useful commands:

```bash
docker compose ps
docker compose logs --tail=100
docker compose exec shelter-agent shelter-agent check-config --quiet
docker compose exec shelter-agent shelter-agent status
docker compose restart shelter-agent
```

Run `test-telegram` only when you intend to send a real test message. `healthcheck` checks whether the running agent has refreshed its liveness marker; it does not prove that every collector can access its data source.

## Configuration reference

The complete sample is [agent.example.toml](../config/agent.example.toml). Change existing sections; duplicate section names are invalid TOML.

| Section | Main settings and defaults |
|---|---|
| `[agent]` | Name defaults to hostname; data retention 30 days; configurable host root |
| `[telegram]` | Bot token, `admin_ids`, optional `notify_chat_ids`, HTTP(S) proxy or custom Bot API URL |
| `[notifications]` | Minimum severity `warning`; critical events bypass mute by default |
| `[monitor]` | Every 30 s; CPU 90% for five checks, RAM 90%, disk 85% warning / 95% critical |
| `[docker]` | Every 30 s; all containers unless watch/ignore patterns narrow the list |
| `[services]` | Every 60 s; `ssh`, `cron`, `docker`; watch failed units |
| `[connectivity]` | TCP probes to `1.1.1.1:53` and `8.8.8.8:53`; three failures before alert |
| `[ssh]` | Automatic journal/file source; 10 failed attempts in 300 s; trusted networks |
| `[firewall]` | Blocked-packet logs; 10 distinct ports within 120 s detects a scan |
| `[connections]` | External connections to configured sensitive ports; every 20 s |
| `[lan]` | Discovery every 300 s; first scan establishes baseline; active scan limited to `max_hosts` |
| `[heartbeat]` | Disabled until an external observer is configured |
| `[actions]` | All containers and monitored services allowed by default; confirmation timeout 60 s |

Secrets can use `[telegram].token_file` or `SHELTER_TELEGRAM_TOKEN`. Native installers set config permissions; Docker users should set `chmod 600 config.toml`. Do not commit working configuration files.

### Notifications

Resource alerts fire on state changes, severity escalation, and recovery. They are not sent every cycle. Lower-severity events can be retained in history without being sent. SSH logins, new LAN devices, recoveries, and agent lifecycle events have explicit notification behavior in the code.

Category toggles still apply except to critical events. Muting normally permits critical events; `[notifications].mute_allows_critical` changes that. Preferences persist in SQLite. Containers already stopped when the agent starts do not alert unless explicitly watched; a running container that stops does.

### SSH, firewall, and LAN

SSH auto mode prefers journald, including `sshd` and newer `sshd-session` identifiers, and falls back to `/var/log/auth.log`. File rotation and journal cursors are tracked. Trusted networks suppress successful-login notifications, not storage. The agent also detects repeated attempts from one IP, distributed bursts, and successful login after repeated failures.

Firewall scan detection needs existing UFW/iptables blocked-packet logging. If UFW is already configured, `sudo ufw logging low` enables logging. Configure access rules before changing a remote server's firewall. The agent itself does not block IPs.

LAN discovery sends UDP probes to trigger ARP and reads the ARP table. It does not require nmap or raw sockets. The first scan establishes a baseline; later new MAC addresses can trigger notifications. Randomized MACs are marked. Docker networks and public VPS subnets are excluded; large subnets are not actively scanned. If automatic selection chooses the wrong network, set `[lan].subnets` explicitly to your real private LAN.

Selected-port monitoring reads the host's TCP connection table. Connections handled inside another Docker network namespace are outside its coverage.

## Actions

The bot accepts fixed operations, not shell input. Authorization uses numeric Telegram user IDs. `/id` is the setup exception and is available publicly.

Mutating operations require a single-use confirmation by the initiating user before the timeout, run one at a time, enforce a cooldown, and produce audit events. Logs can be viewed without confirmation. Use narrow `[actions].containers` patterns and service lists, or disable `[telegram].allow_actions` entirely. Configuration cannot be edited through the bot.

Allowed operations are container start/stop/restart, selected service restarts, Docker prune of dangling images and build cache, and agent restart. Stopping the agent's own container is blocked. Restarting a service such as Docker can affect other workloads; read the confirmation message.

## Heartbeat and watchdog

An observer must run outside the monitored server to detect a full outage before recovery. The agent itself can only report downtime after it starts again. Those reports infer a crash/reboot from saved records; they are not hardware diagnoses.

### External heartbeat service

For a service such as Healthchecks.io, create a check, configure its Telegram integration, and obtain its private ping URL. Check current service limits on the provider's website. Edit the existing section:

```toml
[heartbeat]
enabled = true
method = "GET"
url = "https://hc-ping.com/YOUR_PRIVATE_CHECK_ID"
interval = 60
timeout = 10
```

Restart the agent. Verify `/diag` and the provider's last-received time. Choose a grace period that tolerates brief network delays. The observer's bot sends the outage alert, independently of the bot running on your server.

### Included Shelter Watchdog

Deploy on **another machine**. Copy [watchdog.example.toml](../config/watchdog.example.toml) to `watchdog.toml`, restrict its permissions, then generate a per-agent token:

```bash
cp config/watchdog.example.toml watchdog.toml
chmod 600 watchdog.toml
docker compose -f docker-compose.watchdog.yml build
docker compose -f docker-compose.watchdog.yml run --rm shelter-watchdog watchdog gen-token
```

Set these values in the copied watchdog configuration (replace examples; do not duplicate existing sections):

```toml
[watchdog]
listen = "0.0.0.0"
port = 8787
default_timeout = 300

[telegram]
token = "YOUR_BOT_TOKEN"
chat_ids = [123456789]

[[agents]]
id = "home-server"
name = "Home server"
token = "PASTE_THE_GENERATED_TOKEN_HERE"
```

The token must have at least 24 characters; use `gen-token`. Watchdog only sends Telegram messages and may share the agent's bot token. It does not poll that bot.

On the monitored server, set `[agent].name = "home-server"` to match the watchdog agent ID, then configure:

```toml
[heartbeat]
enabled = true
url = "https://watchdog.example.com/api/v1/heartbeat"
token = "PASTE_THE_SAME_GENERATED_TOKEN_HERE"
method = "POST"
interval = 60
```

Expose watchdog behind a TLS reverse proxy; it serves plain HTTP internally. For a proxy on the same host, change the compose port mapping to `127.0.0.1:8787:8787` while keeping `listen = "0.0.0.0"` inside the container. For a native watchdog, use `listen = "127.0.0.1"`. A Caddy example:

```caddyfile
watchdog.example.com {
    reverse_proxy 127.0.0.1:8787
}
```

Start and validate:

```bash
docker compose -f docker-compose.watchdog.yml up -d
docker compose -f docker-compose.watchdog.yml logs --tail=50
```

Native alternative: `sudo ./scripts/install.sh --watchdog --no-start`, edit `/etc/shelter-watchdog/config.toml`, run `sudo shelter-watchdog check-config`, then `sudo systemctl restart shelter-watchdog`.

Watchdog alerts when heartbeats stop and reports recovery. Its state is stored in `/var/lib/shelter-watchdog/state.json`. A restart grants a fresh timeout to avoid immediate false alarms.

API: `POST|GET /api/v1/heartbeat` uses an agent Bearer token; `GET /api/v1/status` uses the configured `status_token`; `GET /healthz` is a liveness endpoint. Keep tokens and ping URLs private.

## CLI

Global options such as `-c` precede the subcommand:

```text
shelter-agent [-c CONFIG] run
shelter-agent [-c CONFIG] check-config [--quiet]
shelter-agent [-c CONFIG] test-telegram
shelter-agent [-c CONFIG] get-chat-id
shelter-agent status [--json]
shelter-agent [-c CONFIG] sudoers [--user shelter]
shelter-agent [-c CONFIG] healthcheck [--max-age 180]
shelter-watchdog [-c CONFIG] run | check-config | gen-token
```

From a checkout: `python3 -m shelter_monitor agent -c ./config.toml run`. On Python 3.10 install `tomli`; the native installer uses the distribution's `python3-tomli` package.

## Troubleshooting and updates

Start with `/diag` and the table in the [English README](../README_EN.md#troubleshooting).

- Missing systemd access is different from a missing service. The agent may show approximate process-based states; it suppresses service alerts in that mode. Check `/run/systemd` and the actual deployment. Running natively is an alternative if container integration is unsuitable.
- If a compose config mount became a directory, the source config file did not exist before startup. Stop that deployment and create a real config from the sample before restarting; preserve any existing data.
- Exclude irrelevant mount patterns through `[monitor].disk_ignore`.
- The API client expects a Unix socket path, not an HTTP Docker socket-proxy URL.
- For Telegram connectivity problems, configure an HTTP(S) proxy or your own Bot API endpoint; SOCKS is not supported.

Back up your config and SQLite data using a consistent SQLite backup or while the agent is stopped. Fetch tags, select the intended release, then rebuild the Docker deployment or rerun the native installer. Do not remove the persistent volume during an ordinary update.

`scripts/uninstall.sh` removes installed native code and units while retaining config/data by default. Its `--purge` option is destructive; inspect the script and back up data before using it.

## Development

Run tests on Linux, where `/proc`, Unix sockets, and systemd clients are available. See [CI](../.github/workflows/ci.yml). Tests use fake Docker/Telegram endpoints and cover authorization, action confirmations, parsers, alert transitions, LAN filtering, watchdog, and agent polling. They do not replace validation of your actual server permissions and network layout.

```bash
python3 -m unittest discover -s tests -t . -v
ruff check shelter_monitor tests
shellcheck scripts/*.sh
```

Future ideas include a central Hub, historical charts, SMART/RAID, certificate/HTTP checks, and a deb package. These are not features of version 0.1.0.
