#!/usr/bin/env bash
# Shelter Monitor installer for Debian / Ubuntu.
#
#   sudo ./scripts/install.sh               # install / upgrade the agent
#   sudo ./scripts/install.sh --watchdog    # install / upgrade the watchdog (on another machine)
#
# Options:
#   --no-docker-group   do not add the service user to the "docker" group
#   --no-start          install but do not (re)start the service
set -euo pipefail

PREFIX=/opt/shelter-monitor
SERVICE_USER=shelter
COMPONENT=agent
DOCKER_GROUP=1
START=1

for arg in "$@"; do
  case "$arg" in
    --watchdog) COMPONENT=watchdog ;;
    --agent) COMPONENT=agent ;;
    --no-docker-group) DOCKER_GROUP=0 ;;
    --no-start) START=0 ;;
    -h|--help) sed -n '2,11p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

log() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31mxx\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root: sudo $0 $*"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[ -f "$SRC_DIR/shelter_monitor/__init__.py" ] || die "run this script from a checkout of the repository"

if [ "$COMPONENT" = agent ]; then
  NAME=shelter-agent; CONF_DIR=/etc/shelter-agent; EXAMPLE=agent.example.toml
else
  NAME=shelter-watchdog; CONF_DIR=/etc/shelter-watchdog; EXAMPLE=watchdog.example.toml
fi

# --- dependencies ----------------------------------------------------------------
if ! command -v python3 >/dev/null 2>&1; then
  log "installing python3"
  apt-get update -qq && apt-get install -y -qq python3
fi
PY_MINOR=$(python3 -c 'import sys; print(sys.version_info[1] if sys.version_info[0] == 3 else 0)')
[ "$PY_MINOR" -ge 10 ] || die "Python 3.10+ is required (found $(python3 --version))"
if [ "$PY_MINOR" -lt 11 ] && ! python3 -c 'import tomli' 2>/dev/null; then
  log "installing python3-tomli (TOML parser for Python 3.10)"
  apt-get update -qq && apt-get install -y -qq python3-tomli
fi
if [ "$COMPONENT" = agent ] && ! command -v sudo >/dev/null 2>&1; then
  warn "sudo is not installed: restarting services from Telegram will not work until it is (apt install sudo)"
fi

# --- files -----------------------------------------------------------------------
log "installing code to $PREFIX"
mkdir -p "$PREFIX"
rm -rf "$PREFIX/shelter_monitor.new"
cp -a "$SRC_DIR/shelter_monitor" "$PREFIX/shelter_monitor.new"
find "$PREFIX/shelter_monitor.new" -name '__pycache__' -type d -prune -exec rm -rf {} +
rm -rf "$PREFIX/shelter_monitor"
mv "$PREFIX/shelter_monitor.new" "$PREFIX/shelter_monitor"
chown -R root:root "$PREFIX"
chmod -R u=rwX,go=rX "$PREFIX"

for cmd in shelter-agent shelter-watchdog; do
  comp=${cmd#shelter-}
  cat > "/usr/local/bin/$cmd" <<EOF
#!/bin/sh
# Wrapper installed by shelter-monitor install.sh
PYTHONPATH=$PREFIX PYTHONDONTWRITEBYTECODE=1 exec /usr/bin/python3 -m shelter_monitor $comp "\$@"
EOF
  chmod 755 "/usr/local/bin/$cmd"
done

# --- user ------------------------------------------------------------------------
if ! id "$SERVICE_USER" >/dev/null 2>&1; then
  log "creating system user $SERVICE_USER"
  useradd --system --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
fi
if [ "$COMPONENT" = agent ]; then
  # adm: /var/log/auth.log; systemd-journal: sshd logs in journald
  for grp in adm systemd-journal; do
    getent group "$grp" >/dev/null && usermod -aG "$grp" "$SERVICE_USER"
  done
  if [ "$DOCKER_GROUP" = 1 ] && getent group docker >/dev/null; then
    log "adding $SERVICE_USER to the docker group (needed for Docker monitoring)"
    usermod -aG docker "$SERVICE_USER"
  fi
fi

# --- config ----------------------------------------------------------------------
mkdir -p "$CONF_DIR"
if [ ! -f "$CONF_DIR/config.toml" ]; then
  log "creating $CONF_DIR/config.toml from example"
  install -m 0640 -o root -g "$SERVICE_USER" "$SRC_DIR/config/$EXAMPLE" "$CONF_DIR/config.toml"
else
  chown root:"$SERVICE_USER" "$CONF_DIR/config.toml"
  chmod 0640 "$CONF_DIR/config.toml"
fi
install -m 0644 "$SRC_DIR/config/$EXAMPLE" "$CONF_DIR/$EXAMPLE"
chmod 0750 "$CONF_DIR"
chown root:"$SERVICE_USER" "$CONF_DIR"

# --- systemd ---------------------------------------------------------------------
if [ ! -d /run/systemd/system ]; then
  warn "systemd is not running on this machine: unit not installed; run manually: $NAME run"
  exit 0
fi
log "installing systemd unit $NAME.service"
install -m 0644 "$SRC_DIR/packaging/systemd/$NAME.service" "/etc/systemd/system/$NAME.service"
systemctl daemon-reload
systemctl enable "$NAME.service" >/dev/null 2>&1

if [ "$START" = 0 ]; then
  log "installed (not started)"
elif runuser -u "$SERVICE_USER" -- /usr/local/bin/$NAME -c "$CONF_DIR/config.toml" check-config --quiet; then
  log "starting $NAME"
  systemctl restart "$NAME.service"
  sleep 2
  systemctl --no-pager --lines=5 status "$NAME.service" || true
else
  warn "configuration is not complete yet — the service is enabled but not started"
  echo
  echo "Next steps:"
  echo "  1. sudo nano $CONF_DIR/config.toml"
  if [ "$COMPONENT" = agent ]; then
    echo "     - set [telegram].token (from @BotFather)"
    echo "     - set [telegram].admin_ids (run: sudo shelter-agent get-chat-id --token <TOKEN>)"
    echo "  2. sudo shelter-agent check-config && sudo shelter-agent test-telegram"
  else
    echo "     - set [telegram].token, chat_ids and [[agents]] (token: shelter-watchdog gen-token)"
    echo "  2. sudo shelter-watchdog check-config"
  fi
  echo "  3. sudo systemctl restart $NAME && journalctl -u $NAME -f"
fi
