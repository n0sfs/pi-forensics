#!/bin/bash
# ARM Forensic Acquisition Station – touchscreen kiosk launcher
# Waits for nginx/TLS (or local gunicorn) then starts Chromium fullscreen.

set -euo pipefail

export DISPLAY="${DISPLAY:-:0}"
export WAYLAND_DISPLAY="${WAYLAND_DISPLAY:-wayland-0}"
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"

# Best-effort: keep display awake (X11; harmless failure on pure Wayland)
xset s off 2>/dev/null || true
xset -dpms 2>/dev/null || true
xset s noblank 2>/dev/null || true
wlr-randr --output ALL --on 2>/dev/null || true

# Hide idle cursor when unclutter is available
if command -v unclutter >/dev/null 2>&1; then
    unclutter -idle 0.5 -root 2>/dev/null &
fi

# Prefer HTTPS via nginx; fall back to local gunicorn if nginx is not up yet
URL="https://127.0.0.1/"
READY=0
for i in $(seq 1 60); do
    code=$(curl -sk -o /dev/null -w "%{http_code}" "$URL" 2>/dev/null || echo "000")
    if echo "$code" | grep -qE '200|401|403'; then
        READY=1
        break
    fi
    # Fallback probe
    code2=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:5000/" 2>/dev/null || echo "000")
    if echo "$code2" | grep -qE '200|401|403'; then
        URL="http://127.0.0.1:5000/"
        READY=1
        break
    fi
    sleep 1
done

if [ "$READY" -ne 1 ]; then
    echo "[kiosk] Timed out waiting for forensic UI – launching anyway"
fi

# Resolve Chromium binary name (Debian vs Raspberry Pi OS)
if command -v chromium >/dev/null 2>&1; then
    BROWSER="chromium"
elif command -v chromium-browser >/dev/null 2>&1; then
    BROWSER="chromium-browser"
else
    echo "[kiosk] Chromium not found" >&2
    exit 1
fi

# Clear stale Chromium singleton locks that can block relaunch after crash
rm -rf "${HOME}/.config/chromium/Singleton"* 2>/dev/null || true
killall -9 chromium chromium-browser 2>/dev/null || true
sleep 0.5

exec "$BROWSER" \
  --kiosk \
  --ozone-platform=wayland \
  --enable-features=UseOzonePlatform \
  --password-store=basic \
  --use-mock-keychain \
  --no-default-browser-check \
  --no-first-run \
  --ignore-certificate-errors \
  --allow-insecure-localhost \
  --noerrdialogs \
  --disable-infobars \
  --disable-session-crashed-bubble \
  --disable-component-update \
  --check-for-update-interval=31536000 \
  "$URL"
