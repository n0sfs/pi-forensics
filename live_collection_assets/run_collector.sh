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
#
# Optional memory (RAM) capture (AVML, github.com/microsoft/avml, MIT) runs
# BEFORE UAC - memory is the single most volatile artifact this whole
# drive can collect, ahead even of the process list UAC itself collects
# first. This is opt-in, asked interactively right here on the target
# machine (never a choice baked in ahead of time when the USB was built on
# the Pi - the Pi has no way to know this machine's RAM size or this
# drive's free space before now), defaults to No on an empty/non-
# interactive answer, and reuses whatever root/sudo state was already
# negotiated for UAC - it never asks for a second, separate elevation.

set -u
cd "$(dirname "$0")" || exit 1

OUT="./output"
mkdir -p "$OUT"

echo "Pi Forensics Suite - Live Collection (Unix/Linux/macOS)"
echo "UAC profile: ir_triage (a curated incident-response triage set)"
echo ""

# --- Determine privilege once, reused by both memory capture and UAC ---
SUDO_PREFIX=""
PRIVILEGED=0
if [ "$(id -u)" = "0" ]; then
  echo "Running as root - full collection."
  PRIVILEGED=1
elif command -v sudo >/dev/null 2>&1; then
  echo "Attempting to run with sudo (recommended - collects more)..."
  if sudo -n true 2>/dev/null || sudo true 2>/dev/null; then
    SUDO_PREFIX="sudo "
    PRIVILEGED=1
  else
    echo "sudo was declined or unavailable - continuing without root."
    echo "(Collection will be more limited - this is expected and logged.)"
  fi
else
  echo "No sudo available on this system - running without root."
  echo "(Collection will be more limited - this is expected and logged.)"
fi

# --- Optional memory (RAM) capture, before UAC ---
MEMORY_STAGED=""
UNAME_S="$(uname -s 2>/dev/null || echo unknown)"
if [ "$PRIVILEGED" -ne 1 ]; then
  echo ""
  echo "Memory capture: skipped (needs root/sudo, not available on this run)."
elif [ "$UNAME_S" = "Darwin" ]; then
  echo ""
  echo "Memory capture: no viable open-source RAM-imaging tool exists for"
  echo "macOS (System Integrity Protection / Apple Silicon block it) - skipping."
else
  UNAME_M="$(uname -m 2>/dev/null || echo unknown)"
  case "$UNAME_M" in
    x86_64|amd64) AVML_BIN="./uac/memory/avml" ;;
    aarch64|arm64) AVML_BIN="./uac/memory/avml-aarch64" ;;
    *) AVML_BIN="" ;;
  esac
  if [ -z "$AVML_BIN" ]; then
    echo ""
    echo "Memory capture: unsupported architecture ($UNAME_M) - skipping."
  elif [ ! -x "$AVML_BIN" ]; then
    echo ""
    echo "Memory capture: avml was not found on this drive (install.py's"
    echo "vendoring step may not have run, or ran without internet access) - skipping."
  else
    RAM_KB="$(awk '/^MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)"
    FREE_KB="$(df -Pk "$OUT" 2>/dev/null | awk 'NR==2 {print $4}')"
    FREE_KB="${FREE_KB:-0}"
    # Require free space >= RAM size * 1.1 (headroom - AVML's uncompressed
    # output is roughly RAM-sized). Both figures in KB throughout.
    NEED_KB=$((RAM_KB + RAM_KB / 10))
    if [ "$RAM_KB" -le 0 ] || [ "$FREE_KB" -lt "$NEED_KB" ]; then
      echo ""
      echo "Memory capture: skipped - not enough free space on this drive"
      echo "(target has ~$((RAM_KB / 1024)) MB RAM, this drive has ~$((FREE_KB / 1024)) MB free)."
    else
      echo ""
      echo "Memory capture available: target has ~$((RAM_KB / 1024)) MB RAM,"
      echo "this drive has ~$((FREE_KB / 1024)) MB free. This can take several"
      echo "minutes and will use most of that free space."
      printf "Also capture a memory (RAM) image? [y/N] "
      read -r MEM_ANS
      case "$MEM_ANS" in
        [yY]|[yY][eE][sS])
          STAGE_DIR="$OUT/.memory_staging"
          mkdir -p "$STAGE_DIR"
          STAGE_FILE="$STAGE_DIR/memory.lime"
          echo "Capturing memory image (this may take a while)..."
          if $SUDO_PREFIX "$AVML_BIN" acquire "$STAGE_FILE"; then
            MEMORY_STAGED="$STAGE_FILE"
            echo "Memory capture complete - will be added to this run's results below."
          else
            echo "Memory capture failed or was blocked (e.g. kernel lockdown enabled) -"
            echo "continuing without it. This is not fatal to the rest of the collection."
            rm -f "$STAGE_FILE"
          fi
          ;;
        *)
          echo "Skipping memory capture."
          ;;
      esac
    fi
  fi
fi

# --- UAC itself ---
echo ""
UAC_ARGS="-p ir_triage -f none -H -o uac-%hostname%-%os%-%timestamp%"
BEFORE_LISTING="$(ls "$OUT" 2>/dev/null)"
if [ "$PRIVILEGED" -eq 1 ]; then
  # shellcheck disable=SC2086
  $SUDO_PREFIX ./uac $UAC_ARGS "$OUT"
  STATUS=$?
  if [ "$STATUS" -ne 0 ] && [ -n "$SUDO_PREFIX" ]; then
    echo ""
    echo "Elevated run failed or was declined - retrying without root."
    echo "(Collection will be more limited - this is expected and logged.)"
    # shellcheck disable=SC2086
    ./uac $UAC_ARGS -u "$OUT"
    STATUS=$?
  fi
else
  # shellcheck disable=SC2086
  ./uac $UAC_ARGS -u "$OUT"
  STATUS=$?
fi

# --- Identify UAC's own new run directory (its real name, expanded from
#     %hostname%-%os%-%timestamp% by UAC itself, is never known ahead of
#     time) so the memory image and clipboard supplemental can both be
#     merged into it below. Computed once via plain temp files, not bash's
#     `comm -13 <(...) <(...)` process substitution - this script is
#     #!/bin/sh (POSIX/dash on most real Linux/macOS/BSD targets, not
#     bash), so process substitution isn't portable here. ---
RUN_DIR=""
BEFORE_TMP="$(mktemp 2>/dev/null || echo "$OUT/.before_listing.tmp")"
AFTER_TMP="$(mktemp 2>/dev/null || echo "$OUT/.after_listing.tmp")"
printf '%s\n' "$BEFORE_LISTING" | sort > "$BEFORE_TMP"
ls "$OUT" 2>/dev/null | sort > "$AFTER_TMP"
RUN_DIR="$(comm -13 "$BEFORE_TMP" "$AFTER_TMP" 2>/dev/null | grep '^uac-' | head -1)"
rm -f "$BEFORE_TMP" "$AFTER_TMP"

# --- Move the staged memory image into that run directory. ---
if [ -n "$MEMORY_STAGED" ] && [ -f "$MEMORY_STAGED" ]; then
  if [ -n "$RUN_DIR" ] && [ -d "$OUT/$RUN_DIR" ]; then
    mv "$MEMORY_STAGED" "$OUT/$RUN_DIR/memory.lime"
    echo "Memory image added to: $OUT/$RUN_DIR/memory.lime"
  else
    echo ""
    echo "Could not identify UAC's new run directory - the captured memory"
    echo "image was left at: $MEMORY_STAGED (not lost, just not merged into"
    echo "the UAC run folder automatically)."
  fi
  rmdir "$OUT/.memory_staging" 2>/dev/null
fi

# --- Supplemental artifacts UAC itself doesn't collect - clipboard only
#     (see this app's own docs for why the rest of UAC's raw command-text
#     output isn't individually re-parsed by this app yet). Run after UAC
#     completes so a slow/missing clipboard tool never delays the
#     higher-value UAC collection itself. ---
if [ "$STATUS" -eq 0 ] && [ -n "$RUN_DIR" ] && [ -d "$OUT/$RUN_DIR" ]; then
  CLIP=""
  if command -v xclip >/dev/null 2>&1 && [ -n "${DISPLAY:-}" ]; then
    CLIP="$(xclip -o -selection clipboard 2>/dev/null)"
  elif command -v wl-paste >/dev/null 2>&1; then
    CLIP="$(wl-paste 2>/dev/null)"
  elif command -v pbpaste >/dev/null 2>&1; then
    CLIP="$(pbpaste 2>/dev/null)"
  fi
  if [ -n "$CLIP" ]; then
    printf '%s' "$CLIP" > "$OUT/$RUN_DIR/clipboard.txt"
    echo "Clipboard contents added to: $OUT/$RUN_DIR/clipboard.txt"
  else
    echo "Clipboard: no accessible clipboard on this session (headless/no X11-or-Wayland session, or nothing copied) - skipping."
  fi
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
