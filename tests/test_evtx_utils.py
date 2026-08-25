"""core/evtx_utils.py - Windows Event Log (.evtx) parsing (Part C, C2).

Unlike core/registry_utils.py and core/lnk_utils.py, a genuinely valid
.evtx binary is not hand-built here - the EVTX chunk/record binary format
(compressed XML templates, per-chunk checksums) is a materially bigger
undertaking than REGF/LNK's record-offset structures. This module's real
binary-parsing path (parse_evtx_file() end to end) was instead verified
live (2026-08-25) against two real, legitimate .evtx fixtures from
python-evtx's own upstream GitHub test suite (tests/data/security.evtx,
tests/data/system.evtx) - confirmed real 4624/4720/7045 events parsing
with correct fields/timestamps before this module's field-extraction
logic was finalized. What's tested here is everything that doesn't need
a real binary .evtx: the EventData XML extraction (fed a real Event XML
string, exactly matching what record.xml() returns), the discovery walk,
and the allowlist's own shape.

Skipped (not failed) if python-evtx isn't installed - a genuinely optional
pip dependency (Part C), not a platform limitation.
"""
import xml.etree.ElementTree as ET

import pytest

pytest.importorskip("Evtx.Evtx", reason="python-evtx not installed")

import core.evtx_utils as eu

# A real 4624 (successful logon) Event XML string, structurally identical
# to (a trimmed copy of) an actual record confirmed live against
# security.evtx - not fabricated field names.
_REAL_4624_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"></Provider>
<EventID Qualifiers="">4624</EventID>
<Version>0</Version>
<Level>0</Level>
<Task>12544</Task>
<Opcode>0</Opcode>
<Keywords>0x8020000000000000</Keywords>
<TimeCreated SystemTime="2016-07-08 18:12:51.681641+00:00"></TimeCreated>
<EventRecordID>2</EventRecordID>
<Correlation ActivityID="" RelatedActivityID=""></Correlation>
<Execution ProcessID="456" ThreadID="460"></Execution>
<Channel>Security</Channel>
<Computer>37L4247F27-25</Computer>
<Security UserID=""></Security>
</System>
<EventData><Data Name="SubjectUserSid">S-1-0-0</Data>
<Data Name="SubjectUserName">-</Data>
<Data Name="TargetUserName">SYSTEM</Data>
<Data Name="TargetDomainName">NT AUTHORITY</Data>
<Data Name="LogonType">0</Data>
</EventData>
</Event>"""


def test_event_data_dict_extracts_real_name_value_pairs():
    root_el = ET.fromstring(_REAL_4624_XML)
    data = eu._event_data_dict(root_el)
    assert data["TargetUserName"] == "SYSTEM"
    assert data["TargetDomainName"] == "NT AUTHORITY"
    assert data["LogonType"] == "0"
    assert len(data) == 5


def test_event_data_dict_returns_empty_dict_when_no_eventdata_section():
    root_el = ET.fromstring(
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        '<System><EventID>4608</EventID></System></Event>'
    )
    assert eu._event_data_dict(root_el) == {}


def test_event_id_regex_extracts_id_from_a_real_event_xml_string():
    m = eu._EVENT_ID_RE.search(_REAL_4624_XML)
    assert m is not None
    assert m.group(1) == "4624"


def test_event_id_allowlist_covers_the_six_curated_ids_with_valid_shape():
    assert set(eu.EVENT_ID_ALLOWLIST.keys()) == {"4624", "4625", "4688", "4720", "7045", "1102"}
    for event_id, (artifact_type, label, primary_field) in eu.EVENT_ID_ALLOWLIST.items():
        assert artifact_type.startswith("evtx_")
        assert isinstance(label, str) and label
        assert isinstance(primary_field, str) and primary_field
    # 1102 (audit log cleared) - a classic anti-forensic indicator - must
    # be present by name, not silently folded into a generic bucket.
    assert eu.EVENT_ID_ALLOWLIST["1102"][0] == "evtx_audit_log_cleared"


def test_find_evtx_files_matches_by_extension_case_insensitively(tmp_path):
    (tmp_path / "Security.evtx").write_bytes(b"x")
    (tmp_path / "system.EVTX").write_bytes(b"x")
    (tmp_path / "unrelated.log").write_bytes(b"x")
    found, truncated = eu.find_evtx_files(str(tmp_path))
    names = {p.split('/')[-1].split('\\')[-1] for p in found}
    assert names == {"Security.evtx", "system.EVTX"}
    assert truncated is False


def test_parse_evtx_file_on_a_non_evtx_file_returns_empty_not_raises(tmp_path):
    bad_path = tmp_path / "not_real.evtx"
    bad_path.write_bytes(b"not a real evtx file")
    assert eu.parse_evtx_file(str(bad_path)) == []
