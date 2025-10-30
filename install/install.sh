#!/usr/bin/env bash
set -euo pipefail

REPO="nationalsecurityagency/seabee"
BIN_DIR="/usr/sbin"
SERVICE_PATH="/etc/systemd/system/seabee.service"
TAG="v1.2.0" #TODO: update when the new version is released

# Check if exactly one argument is provided
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 {ubuntu-24|fedora-43|rocky-9}"
    exit 1
fi

# Allowed values
ARG="$1"
case "$ARG" in
    ubuntu-24|fedora-43|rocky-9)
        ;;
    *)
        echo "Invalid argument: $ARG"
        echo "Allowed values: ubuntu-24, fedora-43, rocky-9"
        exit 1
        ;;
esac

# Get SeaBee file
echo "Downloading release assets for SeaBee $TAG..."
curl -fsSL "https://github.com/$REPO/releases/download/$TAG/seabee-$ARG" -o seabee_binary
curl -fsSLO "https://github.com/$REPO/releases/download/$TAG/seabeectl"
curl -fsSLO "https://github.com/$REPO/releases/download/$TAG/seabee.service"

echo "Installing binaries..."
install -m 0755 seabee_binary "$BIN_DIR/seabee"
install -m 0755 seabeectl "$BIN_DIR/seabeectl"

echo "Installing systemd service..."
install -m 0644 seabee.service "$SERVICE_PATH"
systemctl daemon-reload

echo "Seabee has been installed."
echo "Before running SeaBee, you will need to create and install a SeaBee Root Key."
echo "See https://code.nsa.gov/seabee/getting_started/ for more information."
