"""core/email_utils.py - real .eml/.mbox files built and parsed via the
standard library (fully self-contained, zero external test-file
dependency), plus a mocked-object test of the PST/OST walk logic (pypff
isn't installed in this dev environment - the same "mock the library's
real, confirmed object shape" pattern this project already uses elsewhere
for subprocess/library-coupled code whose real binary/package isn't
locally available)."""
import email
import mailbox
import datetime

import core.email_utils as eu


def _make_eml_bytes(subject, sender, to, date, body_text, html_fallback=None, attachment=False):
    msg = email.message.EmailMessage()
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = to
    msg['Date'] = date
    if html_fallback and not body_text:
        msg.add_alternative(html_fallback, subtype='html')
    else:
        msg.set_content(body_text)
        if html_fallback:
            msg.add_alternative(html_fallback, subtype='html')
    if attachment:
        msg.add_attachment(b'fake pdf bytes', maintype='application', subtype='pdf', filename='evidence.pdf')
    return msg.as_bytes()


def test_parse_eml_file_extracts_headers_and_body(tmp_path):
    eml_path = tmp_path / "message.eml"
    eml_path.write_bytes(_make_eml_bytes(
        "Re: the plan", "suspect@example.com", "accomplice@example.com",
        "Mon, 30 Aug 2026 12:00:00 -0000", "Meet at the usual place at midnight.",
    ))
    records = eu.parse_eml_file(str(eml_path))
    assert len(records) == 1
    r = records[0]
    assert r["artifact_type"] == "email_message"
    assert r["title"] == "Re: the plan"
    assert r["value"] == "suspect@example.com"
    assert r["extra"]["to"] == "accomplice@example.com"
    assert "midnight" in r["extra"]["body_preview"]
    assert r["extra"]["source_format"] == "eml"
    assert r["timestamp"] is not None


def test_parse_eml_file_counts_a_real_attachment(tmp_path):
    eml_path = tmp_path / "with_attachment.eml"
    eml_path.write_bytes(_make_eml_bytes(
        "Files attached", "a@example.com", "b@example.com",
        "Mon, 30 Aug 2026 12:00:00 -0000", "See attached.", attachment=True,
    ))
    records = eu.parse_eml_file(str(eml_path))
    assert records[0]["extra"]["attachment_count"] == 1


def test_parse_eml_file_falls_back_to_html_body_when_no_plain_text(tmp_path):
    eml_path = tmp_path / "html_only.eml"
    eml_path.write_bytes(_make_eml_bytes(
        "HTML only", "a@example.com", "b@example.com", "Mon, 30 Aug 2026 12:00:00 -0000",
        None, html_fallback="<html><body><p>Real content here</p></body></html>",
    ))
    records = eu.parse_eml_file(str(eml_path))
    assert "Real content here" in records[0]["extra"]["body_preview"]
    assert "<p>" not in records[0]["extra"]["body_preview"]  # tags stripped


def test_parse_eml_file_unreadable_file_returns_empty_not_raises(tmp_path):
    bad_path = tmp_path / "not_real.eml"
    bad_path.write_bytes(b'\xff\xfe\x00\x00garbage')
    # A malformed .eml still parses SOMETHING via email.message_from_binary_file
    # (it's tolerant by design) - the real assertion is that this never raises.
    records = eu.parse_eml_file(str(bad_path))
    assert isinstance(records, list)


def test_parse_mbox_file_extracts_multiple_messages(tmp_path):
    mbox_path = tmp_path / "Inbox.mbox"
    box = mailbox.mbox(str(mbox_path))
    box.lock()
    try:
        for i in range(3):
            msg = mailbox.mboxMessage()
            msg['Subject'] = f'Message {i}'
            msg['From'] = f'sender{i}@example.com'
            msg['Date'] = 'Mon, 30 Aug 2026 12:00:00 -0000'
            msg.set_payload(f'Body of message {i}')
            box.add(msg)
        box.flush()
    finally:
        box.unlock()
        box.close()

    records = eu.parse_mbox_file(str(mbox_path))
    assert len(records) == 3
    titles = {r["title"] for r in records}
    assert titles == {"Message 0", "Message 1", "Message 2"}
    assert all(r["extra"]["source_format"] == "mbox" for r in records)
    # Real bug caught live: mailbox.mbox()'s default factory returns a
    # legacy email.message.Message (no get_content() method at all,
    # unlike parse_eml_file()'s modern EmailMessage/policy.default
    # objects) - every mbox message's body silently came back empty
    # before _extract_body_and_attachments() was fixed to use
    # get_payload(decode=True) instead, which works on both.
    for r in records:
        assert r["extra"]["body_preview"] != ''
        assert "Body" in r["extra"]["body_preview"]


def test_parse_mbox_file_unreadable_path_returns_empty_not_raises(tmp_path):
    assert eu.parse_mbox_file(str(tmp_path / "does_not_exist.mbox")) == []


def test_find_email_files_matches_known_extensions_only(tmp_path):
    (tmp_path / "a.eml").write_bytes(b'x')
    (tmp_path / "b.mbox").write_bytes(b'x')
    (tmp_path / "c.pst").write_bytes(b'x')
    (tmp_path / "d.ost").write_bytes(b'x')
    (tmp_path / "unrelated.txt").write_bytes(b'x')
    found, truncated = eu.find_email_files(str(tmp_path))
    import os
    names = {os.path.basename(p) for p in found}
    assert names == {"a.eml", "b.mbox", "c.pst", "d.ost"}
    assert truncated is False


def test_parse_email_file_dispatches_by_extension(tmp_path):
    eml_path = tmp_path / "x.eml"
    eml_path.write_bytes(_make_eml_bytes("S", "f@x.com", "t@x.com", "Mon, 30 Aug 2026 12:00:00 -0000", "b"))
    assert len(eu.parse_email_file(str(eml_path))) == 1
    # An unrecognized extension dispatches to nothing, not a crash.
    unknown_path = tmp_path / "x.unknown"
    unknown_path.write_bytes(b'x')
    assert eu.parse_email_file(str(unknown_path)) == []


def test_epoch_from_email_date_handles_missing_and_garbage():
    assert eu._epoch_from_email_date(None) is None
    assert eu._epoch_from_email_date('') is None
    assert eu._epoch_from_email_date('not a real date') is None
    assert eu._epoch_from_email_date('Mon, 30 Aug 2026 12:00:00 -0000') is not None


class _FakePffMessage:
    """Mirrors pypff's real, live-confirmed message object API (see this
    module's own docstring) - used since pypff isn't installed in this
    dev environment."""
    def __init__(self, subject, sender, delivery_time, body, attachments=0):
        self._subject, self._sender, self._delivery_time = subject, sender, delivery_time
        self._body, self._attachments = body, attachments

    def get_subject(self): return self._subject
    def get_sender_name(self): return self._sender
    def get_delivery_time(self): return self._delivery_time
    def get_client_submit_time(self): return None
    def get_plain_text_body(self): return self._body
    def get_html_body(self): return None
    def get_number_of_attachments(self): return self._attachments


class _FakePffFolder:
    def __init__(self, messages=None, sub_folders=None):
        self._messages = messages or []
        self._sub_folders = sub_folders or []

    @property
    def number_of_sub_messages(self): return len(self._messages)

    @property
    def number_of_sub_folders(self): return len(self._sub_folders)

    def get_sub_message(self, i): return self._messages[i]
    def get_sub_folder(self, i): return self._sub_folders[i]


def test_walk_pff_folder_extracts_messages_across_nested_folders():
    dt = datetime.datetime(2026, 8, 30, 12, 0, 0)
    inbox = _FakePffFolder(messages=[_FakePffMessage("Top-level msg", "a@x.com", dt, "hello", attachments=2)])
    deleted_items = _FakePffFolder(messages=[_FakePffMessage("Deleted msg", "b@x.com", dt, "goodbye")])
    root = _FakePffFolder(sub_folders=[inbox, deleted_items])

    records = []
    eu._walk_pff_folder(root, records, "pst")
    assert len(records) == 2
    titles = {r["title"] for r in records}
    assert titles == {"Top-level msg", "Deleted msg"}
    top = next(r for r in records if r["title"] == "Top-level msg")
    assert top["extra"]["attachment_count"] == 2
    assert top["timestamp"] is not None


def test_walk_pff_folder_tolerates_one_unreadable_message():
    class _ExplodingMessage(_FakePffMessage):
        def get_subject(self): raise RuntimeError("corrupt record")
    folder = _FakePffFolder(messages=[
        _ExplodingMessage("x", "y", None, "z"),
        _FakePffMessage("Real message", "a@x.com", None, "body"),
    ])
    records = []
    eu._walk_pff_folder(folder, records, "pst")
    assert len(records) == 1
    assert records[0]["title"] == "Real message"


def test_pff_time_to_epoch_handles_none():
    assert eu._pff_time_to_epoch(None) is None
