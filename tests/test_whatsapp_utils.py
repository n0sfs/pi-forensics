"""Tests for core/whatsapp_utils.py. Mocks subprocess.run throughout - no
genuine adb/wadecrypt binary needed to test this module's own request-
shaping/response-handling logic. The real wadecrypt CLI's positional-
argument order and success/failure behavior were already separately,
live-verified via a real synthetic key+crypt14 round trip (see the
module's own docstring) - what this file owns is the wrapper logic
around that confirmed-real shape."""
import subprocess

import core.whatsapp_utils as wa


class _FakeCompletedProcess:
    def __init__(self, returncode=0, stdout='', stderr='', stdout_bytes=None):
        self.returncode = returncode
        self.stdout = stdout_bytes if stdout_bytes is not None else stdout
        self.stderr = stderr


# --- pull_whatsapp_key_file() ---

def test_pull_key_correct_command_construction(monkeypatch):
    seen = {}
    def fake_run(cmd, **kw):
        seen['cmd'] = cmd
        return _FakeCompletedProcess(returncode=0, stdout_bytes=b'a-real-16-byte-k')
    monkeypatch.setattr(subprocess, 'run', fake_run)
    wa.pull_whatsapp_key_file('EMULATOR123', '/tmp/key')
    cmd = seen['cmd']
    assert cmd == ['adb', '-s', 'EMULATOR123', 'shell', 'su', '-c',
                    'cat /data/data/com.whatsapp/files/key']


def test_pull_key_success_writes_bytes_to_dest(tmp_path, monkeypatch):
    dest = tmp_path / 'key'
    monkeypatch.setattr(subprocess, 'run',
                         lambda cmd, **kw: _FakeCompletedProcess(returncode=0, stdout_bytes=b'\x01\x02realkeybytes'))
    result = wa.pull_whatsapp_key_file('SERIAL', str(dest))
    assert result['success'] is True
    assert result['path'] == str(dest)
    assert dest.read_bytes() == b'\x01\x02realkeybytes'


def test_pull_key_nonzero_exit_returns_clean_error(monkeypatch):
    # text=False in the real call (raw device bytes, not decoded text), so
    # res.stderr is genuinely bytes here, matching the real subprocess
    # contract - not a plain str the way most of this app's other
    # subprocess wrappers (text=True) would receive it.
    monkeypatch.setattr(subprocess, 'run', lambda cmd, **kw: _FakeCompletedProcess(
        returncode=1, stderr=b'su: not found'))
    result = wa.pull_whatsapp_key_file('SERIAL', '/tmp/key')
    assert result['success'] is False
    assert 'su: not found' in result['error']


def test_pull_key_nonzero_exit_with_no_stderr_gets_a_helpful_fallback(monkeypatch):
    monkeypatch.setattr(subprocess, 'run', lambda cmd, **kw: _FakeCompletedProcess(returncode=1))
    result = wa.pull_whatsapp_key_file('SERIAL', '/tmp/key')
    assert result['success'] is False
    assert 'rooted' in result['error']


def test_pull_key_empty_output_is_a_clean_error_not_a_zero_byte_file(tmp_path, monkeypatch):
    dest = tmp_path / 'key'
    monkeypatch.setattr(subprocess, 'run', lambda cmd, **kw: _FakeCompletedProcess(returncode=0, stdout_bytes=b''))
    result = wa.pull_whatsapp_key_file('SERIAL', str(dest))
    assert result['success'] is False
    assert not dest.exists()


def test_pull_key_oversized_response_is_rejected_as_likely_su_denial(tmp_path, monkeypatch):
    dest = tmp_path / 'key'
    oversized = b'x' * (wa.WHATSAPP_KEY_MAX_BYTES + 1)
    monkeypatch.setattr(subprocess, 'run', lambda cmd, **kw: _FakeCompletedProcess(returncode=0, stdout_bytes=oversized))
    result = wa.pull_whatsapp_key_file('SERIAL', str(dest))
    assert result['success'] is False
    assert 'su-denial' in result['error']
    assert not dest.exists()


def test_pull_key_timeout_returns_clean_error(monkeypatch):
    def fake_run(cmd, **kw):
        raise subprocess.TimeoutExpired(cmd, kw.get('timeout', 20))
    monkeypatch.setattr(subprocess, 'run', fake_run)
    result = wa.pull_whatsapp_key_file('SERIAL', '/tmp/key')
    assert result['success'] is False
    assert 'Timed out' in result['error']


def test_pull_key_unwritable_dest_returns_clean_error(tmp_path, monkeypatch):
    monkeypatch.setattr(subprocess, 'run', lambda cmd, **kw: _FakeCompletedProcess(returncode=0, stdout_bytes=b'realkey'))
    bad_dest = str(tmp_path / 'no_such_dir' / 'key')
    result = wa.pull_whatsapp_key_file('SERIAL', bad_dest)
    assert result['success'] is False
    assert 'Could not write key file' in result['error']


# --- decrypt_whatsapp_backup() ---

def test_decrypt_missing_binary_returns_clean_error(tmp_path, monkeypatch):
    monkeypatch.setattr(wa, 'WADECRYPT_BIN', str(tmp_path / 'does_not_exist'))
    result = wa.decrypt_whatsapp_backup(str(tmp_path / 'crypt14'), str(tmp_path / 'key'), str(tmp_path / 'out.db'))
    assert result['success'] is False
    assert 'not installed' in result['error']


def test_decrypt_correct_positional_argument_order(tmp_path, monkeypatch):
    # Confirmed real, live-verified order: [keyfile] [encrypted] [decrypted]
    fake_bin = tmp_path / 'wadecrypt'
    fake_bin.write_text('x')
    monkeypatch.setattr(wa, 'WADECRYPT_BIN', str(fake_bin))
    out_path = tmp_path / 'msgstore.db'
    seen = {}
    def fake_run(cmd, **kw):
        seen['cmd'] = cmd
        out_path.write_bytes(b'a decrypted sqlite db')
        return _FakeCompletedProcess(returncode=0)
    monkeypatch.setattr(subprocess, 'run', fake_run)
    wa.decrypt_whatsapp_backup(str(tmp_path / 'msgstore.db.crypt14'), str(tmp_path / 'key'), str(out_path))
    cmd = seen['cmd']
    assert cmd == [str(fake_bin), str(tmp_path / 'key'), str(tmp_path / 'msgstore.db.crypt14'), str(out_path)]


def test_decrypt_success_strips_ansi_codes_from_log(tmp_path, monkeypatch):
    fake_bin = tmp_path / 'wadecrypt'
    fake_bin.write_text('x')
    monkeypatch.setattr(wa, 'WADECRYPT_BIN', str(fake_bin))
    out_path = tmp_path / 'out.db'
    def fake_run(cmd, **kw):
        out_path.write_bytes(b'real decrypted content')
        return _FakeCompletedProcess(returncode=0, stderr='\x1b[32mDecryption successful\x1b[0m')
    monkeypatch.setattr(subprocess, 'run', fake_run)
    result = wa.decrypt_whatsapp_backup(str(tmp_path / 'x.crypt14'), str(tmp_path / 'key'), str(out_path))
    assert result['success'] is True
    assert result['log'] == 'Decryption successful'
    assert '\x1b' not in result['log']


def test_decrypt_nonzero_exit_from_a_real_wrong_key_traceback_is_a_clean_failure(tmp_path, monkeypatch):
    # Real, confirmed live behavior: a wrong/malformed key can make
    # wadecrypt itself raise a raw Python traceback rather than fail
    # gracefully.
    fake_bin = tmp_path / 'wadecrypt'
    fake_bin.write_text('x')
    monkeypatch.setattr(wa, 'WADECRYPT_BIN', str(fake_bin))
    monkeypatch.setattr(subprocess, 'run', lambda cmd, **kw: _FakeCompletedProcess(
        returncode=1, stderr='Traceback (most recent call last):\nvalueError: Invalid key'))
    result = wa.decrypt_whatsapp_backup(str(tmp_path / 'x.crypt14'), str(tmp_path / 'key'), str(tmp_path / 'out.db'))
    assert result['success'] is False
    assert 'Invalid key' in result['error']


def test_decrypt_success_exit_but_no_output_file_is_still_a_failure(tmp_path, monkeypatch):
    # A wrong key can also fail "quietly" with exit 0 and no real output -
    # never trust a success exit code alone.
    fake_bin = tmp_path / 'wadecrypt'
    fake_bin.write_text('x')
    monkeypatch.setattr(wa, 'WADECRYPT_BIN', str(fake_bin))
    monkeypatch.setattr(subprocess, 'run', lambda cmd, **kw: _FakeCompletedProcess(returncode=0))
    result = wa.decrypt_whatsapp_backup(str(tmp_path / 'x.crypt14'), str(tmp_path / 'key'), str(tmp_path / 'out.db'))
    assert result['success'] is False
    assert 'key may not match' in result['error']


def test_decrypt_success_exit_but_empty_output_file_is_still_a_failure(tmp_path, monkeypatch):
    fake_bin = tmp_path / 'wadecrypt'
    fake_bin.write_text('x')
    monkeypatch.setattr(wa, 'WADECRYPT_BIN', str(fake_bin))
    out_path = tmp_path / 'out.db'
    def fake_run(cmd, **kw):
        out_path.write_bytes(b'')  # written but genuinely empty
        return _FakeCompletedProcess(returncode=0)
    monkeypatch.setattr(subprocess, 'run', fake_run)
    result = wa.decrypt_whatsapp_backup(str(tmp_path / 'x.crypt14'), str(tmp_path / 'key'), str(out_path))
    assert result['success'] is False


def test_decrypt_timeout_returns_clean_error(tmp_path, monkeypatch):
    fake_bin = tmp_path / 'wadecrypt'
    fake_bin.write_text('x')
    monkeypatch.setattr(wa, 'WADECRYPT_BIN', str(fake_bin))
    def fake_run(cmd, **kw):
        raise subprocess.TimeoutExpired(cmd, kw.get('timeout', 300))
    monkeypatch.setattr(subprocess, 'run', fake_run)
    result = wa.decrypt_whatsapp_backup(str(tmp_path / 'x.crypt14'), str(tmp_path / 'key'), str(tmp_path / 'out.db'))
    assert result['success'] is False
    assert 'timed out' in result['error']


# --- Native msgstore.db/wa.db parsing (2026-09-04) - real SQLite fixtures
# matching the exact modern schema confirmed directly from this app's own
# pinned ALEAPP source (leapp/ALEAPP/scripts/artifacts/WhatsApp.py), not
# mocked/guessed. ---

import sqlite3


def _build_msgstore_db(path, messages=(), calls=(), chats=None, jids=None):
    """messages: list of dicts with keys matching the `message` table's
    real columns (any subset - missing keys default sensibly). chats:
    {chat_row_id: {'jid_row_id': int, 'subject': str|None}}. jids:
    {jid_row_id: raw_string}. calls: list of dicts matching `call_log`."""
    conn = sqlite3.connect(str(path))
    conn.execute('''CREATE TABLE jid (_id INTEGER PRIMARY KEY, raw_string TEXT)''')
    conn.execute('''CREATE TABLE chat (_id INTEGER PRIMARY KEY, jid_row_id INTEGER, subject TEXT)''')
    conn.execute('''CREATE TABLE message (
        _id INTEGER PRIMARY KEY, chat_row_id INTEGER, from_me INTEGER,
        recipient_count INTEGER, timestamp INTEGER, received_timestamp INTEGER,
        sender_jid_row_id INTEGER, message_type INTEGER, text_data TEXT)''')
    conn.execute('''CREATE TABLE call_log (
        _id INTEGER PRIMARY KEY, timestamp INTEGER, duration INTEGER,
        from_me INTEGER, video_call INTEGER, jid_row_id INTEGER, group_jid_row_id INTEGER)''')
    for jid_id, raw in (jids or {}).items():
        conn.execute('INSERT INTO jid (_id, raw_string) VALUES (?, ?)', (jid_id, raw))
    for chat_id, spec in (chats or {}).items():
        conn.execute('INSERT INTO chat (_id, jid_row_id, subject) VALUES (?, ?, ?)',
                     (chat_id, spec.get('jid_row_id'), spec.get('subject')))
    for m in messages:
        conn.execute('''INSERT INTO message
            (chat_row_id, from_me, recipient_count, timestamp, received_timestamp,
             sender_jid_row_id, message_type, text_data) VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
            (m.get('chat_row_id'), m.get('from_me', 0), m.get('recipient_count', 0),
             m.get('timestamp'), m.get('received_timestamp'), m.get('sender_jid_row_id'),
             m.get('message_type', 0), m.get('text_data')))
    for c in calls:
        conn.execute('''INSERT INTO call_log
            (timestamp, duration, from_me, video_call, jid_row_id, group_jid_row_id)
            VALUES (?, ?, ?, ?, ?, ?)''',
            (c.get('timestamp'), c.get('duration', 0), c.get('from_me', 0),
             c.get('video_call', 0), c.get('jid_row_id'), c.get('group_jid_row_id')))
    conn.commit()
    conn.close()


def _build_wa_db(path, contacts=()):
    conn = sqlite3.connect(str(path))
    conn.execute('''CREATE TABLE wa_contacts (
        jid TEXT, wa_name TEXT, given_name TEXT, family_name TEXT,
        display_name TEXT, number TEXT)''')
    for c in contacts:
        conn.execute('''INSERT INTO wa_contacts
            (jid, wa_name, given_name, family_name, display_name, number)
            VALUES (?, ?, ?, ?, ?, ?)''',
            (c.get('jid'), c.get('wa_name'), c.get('given_name'), c.get('family_name'),
             c.get('display_name'), c.get('number')))
    conn.commit()
    conn.close()


def test_find_whatsapp_databases_finds_both_real_filenames(tmp_path):
    (tmp_path / 'com.whatsapp' / 'databases').mkdir(parents=True)
    (tmp_path / 'com.whatsapp' / 'databases' / 'msgstore.db').write_bytes(b'')
    (tmp_path / 'com.whatsapp' / 'databases' / 'wa.db').write_bytes(b'')
    found = wa.find_whatsapp_databases(str(tmp_path))
    assert len(found['msgstore']) == 1 and found['msgstore'][0].endswith('msgstore.db')
    assert len(found['wa_db']) == 1 and found['wa_db'][0].endswith('wa.db')


def test_parse_whatsapp_messages_one_to_one_no_wa_db_falls_back_to_jid(tmp_path):
    # No sibling wa.db at all - this app's own current WhatsApp-decrypt
    # feature's real, common output shape.
    msgstore = tmp_path / 'msgstore.db'
    _build_msgstore_db(msgstore,
        jids={1: '15551234567@s.whatsapp.net'},
        chats={10: {'jid_row_id': 1, 'subject': None}},
        messages=[{
            'chat_row_id': 10, 'from_me': 0, 'recipient_count': 0,
            'timestamp': 1788000000000, 'sender_jid_row_id': 1,
            'message_type': 0, 'text_data': 'Real message body',
        }])
    records = wa.parse_whatsapp_messages(str(msgstore))
    assert len(records) == 1
    r = records[0]
    assert r['artifact_type'] == 'whatsapp_message'
    assert r['title'] == '15551234567'  # JID stripped of @s.whatsapp.net, no contact name resolved
    assert 'Real message body' in r['value']
    assert '[Incoming, Text]' in r['value']
    assert r['extra']['is_group'] is False
    assert r['extra']['contact_name_resolved'] is False
    assert r['timestamp'] == 1788000000000 / 1000.0


def test_parse_whatsapp_messages_with_sibling_wa_db_resolves_real_contact_name(tmp_path):
    msgstore = tmp_path / 'msgstore.db'
    _build_msgstore_db(msgstore,
        jids={1: '15551234567@s.whatsapp.net'},
        chats={10: {'jid_row_id': 1, 'subject': None}},
        messages=[{
            'chat_row_id': 10, 'from_me': 1, 'recipient_count': 0,
            'timestamp': 1788000100000, 'sender_jid_row_id': 1,
            'message_type': 0, 'text_data': 'Outgoing reply',
        }])
    _build_wa_db(tmp_path / 'wa.db', contacts=[
        {'jid': '15551234567@s.whatsapp.net', 'wa_name': 'Real Verification Contact'},
    ])
    records = wa.parse_whatsapp_messages(str(msgstore))
    assert len(records) == 1
    r = records[0]
    assert r['title'] == 'Real Verification Contact'  # resolved via the attached wa.db
    assert r['extra']['contact_name_resolved'] is True
    assert r['extra']['direction'] == 'Outgoing'
    assert '[Outgoing, Text]' in r['value']


def test_parse_whatsapp_messages_group_chat_uses_chat_subject_as_title(tmp_path):
    msgstore = tmp_path / 'msgstore.db'
    _build_msgstore_db(msgstore,
        jids={1: '15551234567@s.whatsapp.net'},
        chats={20: {'jid_row_id': None, 'subject': 'Real Verification Group'}},
        messages=[{
            'chat_row_id': 20, 'from_me': 0, 'recipient_count': 3,
            'timestamp': 1788000200000, 'sender_jid_row_id': 1,
            'message_type': 1, 'text_data': None,
        }])
    records = wa.parse_whatsapp_messages(str(msgstore))
    assert len(records) == 1
    r = records[0]
    assert r['title'] == 'Real Verification Group'
    assert r['extra']['is_group'] is True
    assert r['extra']['message_type'] == 'Picture'
    assert '(picture, no text)' in r['value']  # no text_data - falls back to a type-labeled placeholder
    # A real, live-caught bug this test now guards against: a group
    # message's SENDER must resolve via message.sender_jid_row_id, not
    # chat.jid_row_id (which for a group identifies the GROUP itself, not
    # a person) - confirmed the raw JID at least reaches extra even with
    # no wa.db attached.
    assert r['extra']['sender_jid'] == '15551234567@s.whatsapp.net'
    assert r['extra']['sender_or_recipient'] == '15551234567'


def test_parse_whatsapp_messages_group_chat_resolves_real_sender_name_via_wa_db(tmp_path):
    # The full regression test for the exact bug found live on the
    # deployed station: with a real wa.db attached, a group message's
    # sender name must resolve correctly via message.sender_jid_row_id -
    # a naive chat.jid_row_id join (the group's own identity, not a
    # person's) would leave this permanently unresolved regardless of
    # whether wa.db is present.
    msgstore = tmp_path / 'msgstore.db'
    _build_msgstore_db(msgstore,
        jids={1: '15551234567@s.whatsapp.net', 2: '15559998888@s.whatsapp.net'},
        chats={20: {'jid_row_id': None, 'subject': 'Real Verification Group'}},
        messages=[{
            'chat_row_id': 20, 'from_me': 0, 'recipient_count': 3,
            'timestamp': 1788000250000, 'sender_jid_row_id': 2,
            'message_type': 0, 'text_data': 'Message from a specific group member',
        }])
    _build_wa_db(tmp_path / 'wa.db', contacts=[
        {'jid': '15551234567@s.whatsapp.net', 'wa_name': 'Wrong Person (would match via chat.jid_row_id)'},
        {'jid': '15559998888@s.whatsapp.net', 'wa_name': 'Correct Group Sender'},
    ])
    records = wa.parse_whatsapp_messages(str(msgstore))
    assert len(records) == 1
    r = records[0]
    assert r['extra']['contact_name_resolved'] is True
    assert r['extra']['sender_or_recipient'] == 'Correct Group Sender'
    assert r['title'] == 'Real Verification Group'  # title still the group subject, not the sender


def test_parse_whatsapp_messages_covers_every_confirmed_message_type_label(tmp_path):
    msgstore = tmp_path / 'msgstore.db'
    type_map = {0: 'Text', 1: 'Picture', 2: 'Audio', 3: 'Video', 5: 'Static Location',
                7: 'System Message', 9: 'Document', 16: 'Live Location'}
    _build_msgstore_db(msgstore,
        jids={1: 'x@s.whatsapp.net'},
        chats={10: {'jid_row_id': 1, 'subject': None}},
        messages=[{'chat_row_id': 10, 'timestamp': 1788000000000 + i, 'sender_jid_row_id': 1,
                   'message_type': t, 'text_data': 'x'} for i, t in enumerate(type_map)])
    records = wa.parse_whatsapp_messages(str(msgstore))
    assert {r['extra']['message_type'] for r in records} == set(type_map.values())


def test_parse_whatsapp_messages_unrecognized_type_falls_back_to_numeric_label(tmp_path):
    msgstore = tmp_path / 'msgstore.db'
    _build_msgstore_db(msgstore,
        jids={1: 'x@s.whatsapp.net'}, chats={10: {'jid_row_id': 1, 'subject': None}},
        messages=[{'chat_row_id': 10, 'timestamp': 1788000000000, 'sender_jid_row_id': 1,
                   'message_type': 99, 'text_data': 'x'}])
    records = wa.parse_whatsapp_messages(str(msgstore))
    assert records[0]['extra']['message_type'] == 'Type 99'


def test_parse_whatsapp_messages_missing_file_returns_empty_not_raises(tmp_path):
    assert wa.parse_whatsapp_messages(str(tmp_path / 'does_not_exist.db')) == []


def test_parse_whatsapp_messages_malformed_file_returns_empty_not_raises(tmp_path):
    bad = tmp_path / 'msgstore.db'
    bad.write_bytes(b'this is not a real sqlite database')
    assert wa.parse_whatsapp_messages(str(bad)) == []


def test_parse_whatsapp_call_log_real_shape_and_direction(tmp_path):
    msgstore = tmp_path / 'msgstore.db'
    _build_msgstore_db(msgstore,
        jids={1: '15559998888@s.whatsapp.net'},
        calls=[{'timestamp': 1788000300000, 'duration': 125, 'from_me': 1,
                'video_call': 1, 'jid_row_id': 1}])
    records = wa.parse_whatsapp_call_log(str(msgstore))
    assert len(records) == 1
    r = records[0]
    assert r['artifact_type'] == 'whatsapp_call_log'
    assert r['title'] == '15559998888'
    assert r['extra']['direction'] == 'Outgoing'
    assert r['extra']['call_type'] == 'Video'
    assert r['extra']['duration_seconds'] == 125
    assert r['timestamp'] == 1788000300000 / 1000.0


def test_parse_whatsapp_call_log_missing_file_returns_empty(tmp_path):
    assert wa.parse_whatsapp_call_log(str(tmp_path / 'nope.db')) == []


def test_parse_whatsapp_contacts_real_name_fallback_chain(tmp_path):
    wa_db = tmp_path / 'wa.db'
    _build_wa_db(wa_db, contacts=[
        {'jid': 'a@s.whatsapp.net', 'given_name': 'Jane', 'family_name': 'Doe'},
        {'jid': 'b@s.whatsapp.net', 'display_name': 'Just A Display Name'},
        {'jid': 'c@s.whatsapp.net', 'number': '+15551112222'},
    ])
    records = wa.parse_whatsapp_contacts(str(wa_db))
    assert len(records) == 3
    titles = {r['title'] for r in records}
    assert titles == {'Jane Doe', 'Just A Display Name', 'c'}  # falls back to the JID-stripped id
    assert all(r['artifact_type'] == 'whatsapp_contact' for r in records)


def test_parse_whatsapp_contacts_missing_file_returns_empty(tmp_path):
    assert wa.parse_whatsapp_contacts(str(tmp_path / 'nope.db')) == []


def test_strip_wa_jid_suffix_handles_individual_and_group_and_none():
    assert wa._strip_wa_jid_suffix('15551234567@s.whatsapp.net') == '15551234567'
    assert wa._strip_wa_jid_suffix('123456-789012@g.us') == '123456-789012'
    assert wa._strip_wa_jid_suffix(None) is None
    assert wa._strip_wa_jid_suffix('') == ''


def test_wa_ms_to_unix_matches_the_real_conversion_and_tolerates_bad_input():
    assert wa._wa_ms_to_unix(1788000000000) == 1788000000.0
    assert wa._wa_ms_to_unix(None) is None
    assert wa._wa_ms_to_unix('not a number') is None
