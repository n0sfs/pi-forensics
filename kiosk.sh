#!/bin/bash

# Define Display environment variables
export DISPLAY=${DISPLAY:-:0}
export WAYLAND_DISPLAY=${WAYLAND_DISPLAY:-wayland-0}

# Safely attempt X11 power settings (suppress errors if on Wayland / missing extension)
xset s off 2>/dev/null || true
xset -dpms 2>/dev/null || true
xset s noblank 2>/dev/null || true

# Hide idle mouse cursor if unclutter is available
unclutter -idle 0.5 -root 2>/dev/null &

# Wait for Flask web app background service to start on port 5000
until curl --output /dev/null --silent --head --fail http://localhost:5000; do
    sleep 1
done

# Detect whether system uses 'chromium' or 'chromium-browser' binary
if command -v chromium &> /dev/null; then
    BROWSER="chromium"
elif command -v chromium-browser &> /dev/null; then
    BROWSER="chromium-browser"
else
    echo "Chromium browser not found!"
    exit 1
fi

# Launch Chromium in Fullscreen Kiosk Mode
$BROWSER --kiosk \
         --noerrdialogs \
         --disable-infobars \
         --no-first-run \
         --check-for-update-interval=31536000 \
         http://localhost:5000