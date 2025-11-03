#!/usr/bin/env bash
set -euo pipefail

seabeectl clean all
rm /usr/sbin/seabeectl
rm /usr/sbin/seabee
rm /etc/systemd/system/seabee.service
systemctl daemon-reload
echo "Seabee has been uninstalled."
