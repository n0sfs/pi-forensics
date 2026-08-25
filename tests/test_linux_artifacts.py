"""core/linux_artifacts.py - Linux forensic artifact parsing (shell
history, /etc/passwd, cron jobs, auth.log, wtmp login records).

Unlike every prior Windows-artifact test file, 4 of these 5 types are
plain text - trivial to fixture directly, no binary-container-building
needed. wtmp is the one binary format, built from the same verified
400-byte layout core/linux_artifacts.py itself uses.

No skip guard needed - this module is pure stdlib, no optional pip
dependency.
"""
import struct
import time

import core.linux_artifacts as la


# --- Shell history ---

def test_find_shell_history_matches_known_filenames(tmp_path):
    (tmp_path / ".bash_history").write_text("ls -la\n")
    (tmp_path / ".zsh_history").write_text("whoami\n")
    (tmp_path / "unrelated_history.txt").write_text("x\n")
    found, truncated = la.find_linux_shell_history_files(str(tmp_path))
    names = {p.split('/')[-1].split('\\')[-1] for p in found}
    assert names == {".bash_history", ".zsh_history"}
    assert truncated is False


def test_parse_shell_history_without_timestamps(tmp_path):
    p = tmp_path / ".bash_history"
    p.write_text("ls -la\ncd /tmp\nrm -rf /important_data\n")
    records = la.parse_linux_shell_history_file(str(p))
    assert [r["title"] for r in records] == ["ls -la", "cd /tmp", "rm -rf /important_data"]
    assert all(r["timestamp"] is None for r in records)


def test_parse_shell_history_with_histtimeformat_markers(tmp_path):
    p = tmp_path / ".bash_history"
    p.write_text("#1700000000\nls -la\n#1700000100\nrm -rf /\n")
    records = la.parse_linux_shell_history_file(str(p))
    assert len(records) == 2
    assert records[0]["title"] == "ls -la"
    assert records[0]["timestamp"] == 1700000000.0
    assert records[1]["title"] == "rm -rf /"
    assert records[1]["timestamp"] == 1700000100.0


# --- /etc/passwd ---

def test_find_passwd_requires_etc_parent_directory(tmp_path):
    real = tmp_path / "etc"
    real.mkdir()
    (real / "passwd").write_text("root:x:0:0:root:/root:/bin/bash\n")
    # A same-named file NOT under an 'etc' directory must not match -
    # the exact false-positive scenario this discovery function guards
    # against (an unrelated file that happens to be named "passwd").
    other = tmp_path / "somewhere_else"
    other.mkdir()
    (other / "passwd").write_text("not a real passwd file\n")
    found, truncated = la.find_linux_passwd_files(str(tmp_path))
    assert len(found) == 1
    assert found[0].endswith("etc/passwd") or found[0].endswith("etc\\passwd")


def test_parse_passwd_extracts_real_account_fields(tmp_path):
    p = tmp_path / "passwd"
    p.write_text(
        "# comment line\n"
        "\n"
        "root:x:0:0:root:/root:/bin/bash\n"
        "suspect:x:1000:1000:Suspect User,,,:/home/suspect:/bin/bash\n"
    )
    records = la.parse_linux_passwd_file(str(p))
    assert len(records) == 2
    assert records[0]["title"] == "root"
    assert records[1]["title"] == "suspect"
    assert records[1]["extra"]["home"] == "/home/suspect"
    assert records[1]["extra"]["shell"] == "/bin/bash"
    assert all(r["timestamp"] is not None for r in records)  # file mtime proxy
    assert all(r["extra"]["timestamp_is_file_mtime"] for r in records)


# --- Cron ---

def test_find_cron_files_matches_cron_d_and_spool_and_crontab(tmp_path):
    (tmp_path / "etc" / "cron.d").mkdir(parents=True)
    (tmp_path / "etc" / "cron.d" / "myjob").write_text("* * * * * root echo hi\n")
    (tmp_path / "var" / "spool" / "cron" / "crontabs").mkdir(parents=True)
    (tmp_path / "var" / "spool" / "cron" / "crontabs" / "suspect").write_text("0 3 * * * /tmp/exfil.sh\n")
    (tmp_path / "etc").mkdir(exist_ok=True) if not (tmp_path / "etc").exists() else None
    (tmp_path / "etc" / "crontab").write_text("PATH=/usr/bin\n* * * * * root /usr/bin/cleanup\n")
    (tmp_path / "unrelated.txt").write_text("x\n")
    found, truncated = la.find_linux_cron_files(str(tmp_path))
    assert len(found) == 3
    assert truncated is False


def test_parse_cron_skips_comments_blank_and_env_assignments(tmp_path):
    p = tmp_path / "crontab"
    p.write_text(
        "# a comment\n"
        "\n"
        "PATH=/usr/bin:/bin\n"
        "SHELL=/bin/sh\n"
        "0 3 * * * root /usr/bin/backup.sh\n"
        "*/5 * * * * suspect /tmp/beacon.sh\n"
    )
    records = la.parse_linux_cron_file(str(p))
    assert len(records) == 2
    assert "backup.sh" in records[0]["title"]
    assert "beacon.sh" in records[1]["title"]


# --- auth.log ---

def test_find_auth_log_requires_log_parent_and_skips_compressed(tmp_path):
    logdir = tmp_path / "var" / "log"
    logdir.mkdir(parents=True)
    (logdir / "auth.log").write_text("x\n")
    (logdir / "auth.log.1").write_text("x\n")
    (logdir / "auth.log.2.gz").write_text("x\n")
    (logdir / "secure").write_text("x\n")
    other = tmp_path / "not_log_dir"
    other.mkdir()
    (other / "auth.log").write_text("x\n")
    found, truncated = la.find_linux_auth_log_files(str(tmp_path))
    names = {p.split('/')[-1].split('\\')[-1] for p in found}
    # both compressed and uncompressed are discovered (the compressed skip
    # happens inside parse_linux_auth_log_file, not the discovery step) -
    # find_* here should still surface auth.log/auth.log.1/auth.log.2.gz/secure,
    # never the one outside a 'log' directory.
    assert names == {"auth.log", "auth.log.1", "auth.log.2.gz", "secure"}


def test_parse_auth_log_skips_compressed_file_gracefully(tmp_path):
    p = tmp_path / "auth.log.1.gz"
    p.write_bytes(b"\x1f\x8b\x08\x00fake gzip bytes")
    assert la.parse_linux_auth_log_file(str(p)) == []


def test_parse_auth_log_extracts_curated_event_kinds(tmp_path):
    p = tmp_path / "auth.log"
    p.write_text(
        "Aug 20 14:03:11 webserver sshd[1234]: Accepted password for admin from 10.0.0.5\n"
        "Aug 20 14:05:22 webserver sshd[1234]: Failed password for invalid user root from 203.0.113.9\n"
        "Aug 20 14:06:00 webserver sudo:  admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/rm -rf /var/log\n"
        "Aug 20 14:07:00 webserver systemd-logind: New session 5 opened for user admin.\n"
        "Aug 20 14:08:00 webserver systemd-logind: session closed for user admin\n"
        "Aug 20 14:09:00 webserver kernel: unrelated line with no known pattern\n"
    )
    # Set mtime to a known date so the year-inference is deterministic.
    import os
    mtime = time.mktime((2026, 8, 20, 15, 0, 0, 0, 0, -1))
    os.utime(str(p), (mtime, mtime))

    records = la.parse_linux_auth_log_file(str(p))
    kinds = [r["extra"]["event_kind"] for r in records]
    assert kinds == ["ssh_login_success", "ssh_login_failure", "sudo_command", "session_opened", "session_closed"]
    assert all(r["timestamp"] is not None for r in records)
    # confirm real year inference: August (month 8) is not after the
    # mtime's month (8), so year stays 2026, not rolled back.
    ts_struct = time.localtime(records[0]["timestamp"])
    assert ts_struct.tm_year == 2026
    assert ts_struct.tm_mon == 8
    assert ts_struct.tm_mday == 20


def test_parse_auth_log_session_opened_handles_both_pam_and_systemd_logind_phrasing(tmp_path):
    p = tmp_path / "auth.log"
    p.write_text(
        "Aug 20 14:00:00 host sshd[1]: pam_unix(sshd:session): session opened for user admin(uid=1000) by (uid=0)\n"
        "Aug 20 14:01:00 host systemd-logind[1]: New session 5 opened for user admin.\n"
    )
    import os
    mtime = time.mktime((2026, 8, 20, 15, 0, 0, 0, 0, -1))
    os.utime(str(p), (mtime, mtime))
    records = la.parse_linux_auth_log_file(str(p))
    assert len(records) == 2
    assert all(r["extra"]["event_kind"] == "session_opened" for r in records)


def test_infer_syslog_year_handles_december_to_january_rollover():
    # File's own mtime is January (rotated at year start) - a log LINE
    # dated December must be inferred as the PREVIOUS year, not the
    # mtime's own year.
    mtime = time.mktime((2027, 1, 2, 0, 0, 0, 0, 0, -1))
    assert la._infer_syslog_year(12, mtime) == 2026  # December line -> previous year
    assert la._infer_syslog_year(1, mtime) == 2027    # January line -> same year as mtime


# --- wtmp (Experimental) ---

def _build_utmp_record(ut_type, pid, line, uid_field, user, host, session, sec, usec):
    return struct.pack(
        '<h2xi32s4s32s256shhqqq4i24x',
        ut_type, pid,
        line.encode()[:32].ljust(32, b'\x00'),
        uid_field.encode()[:4].ljust(4, b'\x00'),
        user.encode()[:32].ljust(32, b'\x00'),
        host.encode()[:256].ljust(256, b'\x00'),
        0, 0,  # exit status
        session, sec, usec,
        0, 0, 0, 0,  # addr_v6
    )


def test_build_utmp_record_matches_verified_400_byte_size():
    raw = _build_utmp_record(7, 1234, "pts/0", "ts/0", "suspect", "10.0.0.5", 1, 1700000000, 0)
    assert len(raw) == 400


def test_parse_wtmp_extracts_real_login_and_skips_non_login_types(tmp_path):
    p = tmp_path / "wtmp"
    data = b""
    data += _build_utmp_record(2, 0, "~", "~", "reboot", "", 0, 1699999000, 0)  # BOOT_TIME - skipped
    data += _build_utmp_record(7, 1234, "pts/0", "ts/0", "suspect", "10.0.0.5", 1, 1700000000, 0)  # real login
    data += _build_utmp_record(8, 1234, "pts/0", "ts/0", "", "", 1, 1700003600, 0)  # DEAD_PROCESS - skipped
    p.write_bytes(data)
    records = la.parse_linux_wtmp_file(str(p))
    assert len(records) == 1
    assert "suspect" in records[0]["title"]
    assert records[0]["extra"]["host"] == "10.0.0.5"
    assert records[0]["timestamp"] == 1700000000.0


def test_parse_wtmp_rejects_wrong_size_file_without_guessing(tmp_path):
    p = tmp_path / "wtmp"
    p.write_bytes(b"\x00" * 137)  # not a multiple of 400
    records = la.parse_linux_wtmp_file(str(p))
    assert len(records) == 1
    assert records[0]["extra"]["layout_check_failed"] is True
    assert "not a multiple" in records[0]["extra"]["reason"]


def test_parse_wtmp_rejects_plausible_size_but_garbage_content(tmp_path):
    # Exactly 400 bytes (passes the size check) but not real utmp data -
    # the self-check gate (not just the size guard) must still catch this.
    p = tmp_path / "wtmp"
    p.write_bytes(b"\xff" * 400)
    records = la.parse_linux_wtmp_file(str(p))
    assert len(records) == 1
    assert records[0]["extra"]["layout_check_failed"] is True


def test_find_wtmp_files_requires_log_parent_directory(tmp_path):
    logdir = tmp_path / "var" / "log"
    logdir.mkdir(parents=True)
    (logdir / "wtmp").write_bytes(b"\x00" * 400)
    (logdir / "btmp").write_bytes(b"\x00" * 400)
    other = tmp_path / "elsewhere"
    other.mkdir()
    (other / "wtmp").write_bytes(b"\x00" * 400)
    found, truncated = la.find_linux_wtmp_files(str(tmp_path))
    assert len(found) == 2
