#!/bin/sh
# Pi Forensics Suite - Live Collection USB, Unix/Linux/macOS/BSD launcher.
#
# Runs UAC (Unix-like Artifacts Collector, https://github.com/tclahr/uac,
# Apache License 2.0) against THIS machine and writes results back onto
# this same USB drive, under ./output/. Nothing here ever touches a
# network. This wrapper never modifies the target system's own files -
# it only reads from it and writes into ./output/ on this removable
# drive. Read it (and, if you like, ./uac itself - it's plain shell)
# before running it on a system you don't already understand.
#
# Tries root/sudo first (UAC collects more with root - process memory
# maps, more log locations it might not otherwise be able to read), and
# automatically falls back to a non-root run (UAC's own -u/
# --run-as-non-root flag) if root access isn't available or is declined -
# never fails outright just because root wasn't available, matching this
# app's own "collect what's available, disclose what wasn't" posture.

set -u
cd "$(dirname "$0")" || exit 1

OUT="./output"
mkdir -p "$OUT"

echo "Pi Forensics Suite - Live Collection (Unix/Linux/macOS)"
echo "UAC profile: ir_triage (a curated incident-response triage set)"
echo ""

UAC_ARGS="-p ir_triage -f none -H -o uac-%hostname%-%os%-%timestamp%"

if [ "$(id -u)" = "0" ]; then
  echo "Running as root - full collection."
  # shellcheck disable=SC2086
  ./uac $UAC_ARGS "$OUT"
  STATUS=$?
elif command -v sudo >/dev/null 2>&1; then
  echo "Attempting to run with sudo (recommended - collects more)..."
  # shellcheck disable=SC2086
  sudo ./uac $UAC_ARGS "$OUT"
  STATUS=$?
  if [ "$STATUS" -ne 0 ]; then
    echo ""
    echo "Elevated run failed or was declined - retrying without root."
    echo "(Collection will be more limited - this is expected and logged.)"
    # shellcheck disable=SC2086
    ./uac $UAC_ARGS -u "$OUT"
    STATUS=$?
  fi
else
  echo "No sudo available on this system - running without root."
  echo "(Collection will be more limited - this is expected and logged.)"
  # shellcheck disable=SC2086
  ./uac $UAC_ARGS -u "$OUT"
  STATUS=$?
fi

echo ""
if [ "$STATUS" -eq 0 ]; then
  echo "Collection complete. Results are in: $(pwd)/$OUT"
  echo "Safely unmount/eject this drive, then plug it back into the"
  echo "Pi Forensics Suite station and use 'Import Collection Results'."
else
  echo "Collection reported an error (exit code $STATUS)."
  echo "See the output above, and uac.log inside the output folder if one was created."
fi

exit "$STATUS"
