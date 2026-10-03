"""Bounded `strings` runs for File Explorer and the image browser (2026-10-02).

Both routes used subprocess.run(capture_output=True) and kept the first 1000
lines - after buffering ALL of the output. On a multi-GB file that is hundreds
of megabytes of Python strings on a 1 GB Pi, enough to push the one gunicorn
worker (and every job it is running) out of memory. This reads the output as it
arrives, stops the process once it has enough, and enforces the time limit on
the process itself.
"""
import subprocess
import threading

STRINGS_MAX_LINES = 1000
STRINGS_MAX_LINE_CHARS = 2000


def strings_first_lines(path, max_lines=STRINGS_MAX_LINES, min_len=6, timeout=60):
    """Returns (lines, more, timed_out): up to max_lines lines of `strings`
    output (each cut to STRINGS_MAX_LINE_CHARS, marked), whether there was more
    output than that, and whether the time limit stopped it."""
    proc = subprocess.Popen(['strings', '-n', str(min_len), path], stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, text=True, errors='replace')
    timed_out = threading.Event()

    def _expire():
        timed_out.set()
        proc.kill()

    timer = threading.Timer(timeout, _expire)
    timer.start()
    lines, more = [], False
    try:
        for line in proc.stdout:
            if len(lines) >= max_lines:
                more = True
                break
            line = line.rstrip('\n')
            if len(line) > STRINGS_MAX_LINE_CHARS:
                line = line[:STRINGS_MAX_LINE_CHARS] + ' [... line cut ...]'
            lines.append(line)
    finally:
        timer.cancel()
        if proc.poll() is None:
            proc.kill()
        proc.stdout.close()
        proc.wait()
    return lines, more, timed_out.is_set()


def format_strings_output(lines, more, timed_out):
    """The text both routes show, with every limit stated."""
    output = "\n".join(lines)
    if more:
        output += f"\n\n[... output continues - only the first {len(lines)} lines are shown ...]"
    if timed_out:
        output += "\n\n[... strings was stopped at its time limit - the output above is incomplete ...]"
    return output or "[no printable strings found]"


CAPPED_OUTPUT_MAX_BYTES = 2 * 1024 * 1024


def run_capped(cmd, timeout, max_bytes=CAPPED_OUTPUT_MAX_BYTES):
    """Runs cmd (stderr merged into stdout) keeping at most max_bytes of its
    output - the same reasoning as strings_first_lines() above, for binwalk and
    clamscan (2026-10-02): subprocess.run(capture_output=True) held all of it.
    Returns (text, returncode, truncated, timed_out); a stopped process has
    returncode None."""
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    timed_out = threading.Event()

    def _expire():
        timed_out.set()
        proc.kill()

    timer = threading.Timer(timeout, _expire)
    timer.start()
    chunks, size, truncated = [], 0, False
    try:
        while True:
            block = proc.stdout.read(65536)
            if not block:
                break
            if size + len(block) > max_bytes:
                chunks.append(block[:max_bytes - size])
                truncated = True
                proc.kill()
                break
            chunks.append(block)
            size += len(block)
    finally:
        timer.cancel()
        if proc.poll() is None:
            proc.kill()
        proc.stdout.close()
        proc.wait()
    rc = None if (truncated or timed_out.is_set()) else proc.returncode
    text = b"".join(chunks).decode('utf-8', errors='replace').strip()
    if truncated:
        text += f"\n\n[... output cut at {max_bytes // (1024 * 1024)} MB - the tool was stopped there ...]"
    if timed_out.is_set():
        text += "\n\n[... stopped at its time limit - the output above is incomplete ...]"
    return text, rc, truncated, timed_out.is_set()
