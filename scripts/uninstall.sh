#!/usr/bin/env bash
# Remove Shelter Monitor (agent and/or watchdog).
#   sudo ./scripts/uninstall.sh           # keep configs and data
#   sudo ./scripts/uninstall.sh --purge   # also delete /etc/shelter-*, /var/lib/shelter-*, the user and sudoers rule
set -euo pipefail
PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }

for name in shelter-agent shelter-watchdog; do
  if [ -f "/etc/systemd/system/$name.service" ]; then
    systemctl disable --now "$name.service" >/dev/null 2>&1 || true
    rm -f "/etc/systemd/system/$name.service"
  fi
  rm -f "/usr/local/bin/$name"
done
systemctl daemon-reload 2>/dev/null || true
rm -rf /opt/shelter-monitor

if [ "$PURGE" = 1 ]; then
  rm -rf /etc/shelter-agent /etc/shelter-watchdog /var/lib/shelter-agent /var/lib/shelter-watchdog
  rm -f /etc/sudoers.d/shelter-agent
  id shelter >/dev/null 2>&1 && userdel shelter || true
  echo "Shelter Monitor removed completely."
else
  echo "Shelter Monitor removed. Configs (/etc/shelter-*) and data (/var/lib/shelter-*) were kept; use --purge to delete them."
fi
