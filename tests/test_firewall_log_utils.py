"""Tests for core/firewall_log_utils.py, built against real pfirewall.log
content matching the real, confirmed W3C-Extended-Log-File-Format-style
structure (a #Fields: header declaring the actual column order, per
Microsoft's own official documentation) - not mocks."""
import datetime

import core.firewall_log_utils as flu

_REAL_HEADER = (
    "#Version: 1.5\n"
    "#Software: Microsoft Windows Firewall\n"
    "#Time Format: Local\n"
    "#Fields: date time action protocol src-ip dst-ip src-port dst-port size "
    "tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path\n"
)


def test_parse_firewall_log_standard_field_order(tmp_path):
    row = "2026-08-30 14:22:07 ALLOW TCP 192.168.1.50 8.8.8.8 51422 443 0 - - - - - - - RECEIVE\n"
    p = tmp_path / 'pfirewall.log'
    p.write_text(_REAL_HEADER + row, encoding='utf-8')

    records = flu.parse_firewall_log_file(str(p))
    assert len(records) == 1
    r = records[0]
    assert r["artifact_type"] == "firewall_connection_log"
    assert "ALLOW TCP: 192.168.1.50:51422 -> 8.8.8.8:443" == r["title"]
    assert r["extra"]["action"] == "ALLOW"
    assert r["extra"]["protocol"] == "TCP"
    assert r["extra"]["dst-port"] == "443"
    assert r["extra"]["size"] == "0"
    assert r["extra"]["tcpflags"] is None  # a literal '-' column must decode to None, not the string '-'
    expected_ts = datetime.datetime(2026, 8, 30, 14, 22, 7, tzinfo=datetime.timezone.utc).timestamp()
    assert r["timestamp"] == expected_ts


def test_parse_firewall_log_respects_a_custom_reordered_field_header(tmp_path):
    # The whole point of always reading #Fields: rather than assuming a
    # fixed order - a station where an admin logged a DIFFERENT, smaller,
    # differently-ordered field set must still parse correctly.
    header = "#Fields: date time action src-ip dst-ip\n"
    row = "2026-08-30 09:00:00 DROP 10.0.0.5 10.0.0.99\n"
    p = tmp_path / 'pfirewall.log'
    p.write_text(header + row, encoding='utf-8')

    records = flu.parse_firewall_log_file(str(p))
    assert len(records) == 1
    r = records[0]
    assert r["extra"] == {"date": "2026-08-30", "time": "09:00:00", "action": "DROP",
                           "src-ip": "10.0.0.5", "dst-ip": "10.0.0.99"}
    assert r["title"] == "DROP ?: 10.0.0.5 -> 10.0.0.99"  # protocol column absent entirely -> '?'


def test_parse_firewall_log_no_fields_header_returns_empty(tmp_path):
    p = tmp_path / 'pfirewall.log'
    p.write_text("just some random text, not a real firewall log at all\n", encoding='utf-8')
    assert flu.parse_firewall_log_file(str(p)) == []


def test_parse_firewall_log_missing_file_returns_empty(tmp_path):
    assert flu.parse_firewall_log_file(str(tmp_path / 'pfirewall.log')) == []


def test_parse_firewall_log_malformed_row_is_skipped_not_fatal(tmp_path):
    rows = (
        "2026-08-30 14:22:07 ALLOW TCP 192.168.1.50 8.8.8.8 51422 443 0 - - - - - - - RECEIVE\n"
        "totally malformed garbage row with way too few columns\n"
        "2026-08-30 14:22:10 ALLOW TCP 192.168.1.51 8.8.4.4 51423 443 0 - - - - - - - RECEIVE\n"
    )
    p = tmp_path / 'pfirewall.log'
    p.write_text(_REAL_HEADER + rows, encoding='utf-8')
    records = flu.parse_firewall_log_file(str(p))
    # Every row is still recorded (the row itself is preserved as raw text
    # in "value" regardless of whether it maps cleanly onto every column) -
    # this app's own established "never silently drop a row" convention.
    assert len(records) == 3


def test_parse_firewall_log_caps_row_count(tmp_path):
    rows = "\n".join(
        f"2026-08-30 14:22:{i % 60:02d} ALLOW TCP 192.168.1.1 8.8.8.8 1234 443 0 - - - - - - - RECEIVE"
        for i in range(flu.FIREWALL_LOG_MAX_ROWS + 200))
    p = tmp_path / 'pfirewall.log'
    p.write_text(_REAL_HEADER + rows + "\n", encoding='utf-8')
    records = flu.parse_firewall_log_file(str(p))
    assert len(records) == flu.FIREWALL_LOG_MAX_ROWS


def test_find_firewall_log_files_matches_both_real_filenames(tmp_path):
    (tmp_path / 'pfirewall.log').write_bytes(b'x')
    (tmp_path / 'PFIREWALL.LOG.OLD').write_bytes(b'x')
    (tmp_path / 'unrelated.log').write_bytes(b'x')
    found, truncated = flu.find_firewall_log_files(str(tmp_path))
    basenames = sorted(p.split('/')[-1].split('\\')[-1] for p in found)
    assert basenames == ['PFIREWALL.LOG.OLD', 'pfirewall.log']
    assert truncated is False


def test_find_firewall_log_files_skips_recovery_tool_output_dirs(tmp_path):
    skip_dir = tmp_path / 'evidence_foremost'
    skip_dir.mkdir()
    (skip_dir / 'pfirewall.log').write_bytes(b'x')
    real_dir = tmp_path / 'real'
    real_dir.mkdir()
    (real_dir / 'pfirewall.log').write_bytes(b'x')
    found, _truncated = flu.find_firewall_log_files(str(tmp_path))
    assert len(found) == 1
    assert 'real' in found[0]
