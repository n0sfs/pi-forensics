"""Email artifact parsing - MBOX/EML via the Python standard library (zero
new dependencies), and Outlook PST/OST via libpff-python (PyPI: libpff-
python, confirmed live-installable on the Pi's real ARM64/Debian-trixie
venv - a real source compile, not a prebuilt wheel, but confirmed clean
before adding it to requirements.txt). Mirrors every other artifact-parser
module's exact {artifact_type, title, url, value, timestamp, extra} record
shape, so the shared, already-generic _record_parsed_artifacts()/
parsed_artifacts table and File Views' "Parsed Artifacts" rendering need
zero changes to support this new source.

pypff's real API was confirmed live before writing this module (not
assumed from documentation): pypff.file().open(path) ->
get_root_folder() -> .sub_folders / .sub_messages (recursive), and a
message object's .get_subject()/.get_sender_name()/.get_delivery_time()/
.get_client_submit_time()/.get_plain_text_body()/.get_html_body()/
.get_number_of_attachments() - all confirmed real methods via direct
introspection of the installed package.

Deliberately does NOT cover standalone .msg files (Outlook's single-
message format) - like Jump Lists (.automaticDestinations-ms), .msg is an
OLE2/Compound File Binary container, and building a trustworthy synthetic
OLE test fixture was out of scope for this pass (see this module's sibling
scoping note in core/registry_utils.py's own commit history) - a real,
disclosed gap, not silently assumed covered.
"""
import os
import re
import email
import email.utils
import email.policy
import mailbox
from datetime import datetime, timezone

EMAIL_SCAN_MAX_CANDIDATES = 500
EMAIL_MBOX_MAX_MESSAGES_PER_FILE = 5_000
EMAIL_PST_MAX_MESSAGES = 10_000
EMAIL_BODY_PREVIEW_MAX_CHARS = 500

_SCAN_SKIP_DIR_NAMES = {'RECOVERED_FILES'}
_SCAN_SKIP_DIR_SUFFIXES = ('_photorec', '_foremost', '_scalpel', '_triagescan')

_EML_EXTENSIONS = ('.eml',)
_MBOX_EXTENSIONS = ('.mbox',)
_PST_EXTENSIONS = ('.pst', '.ost')

_HTML_TAG_RE = re.compile(r'<[^>]+>')


def find_email_files(root_dir):
    """Recursively finds real files matching a known email-container
    extension (.eml/.mbox/.pst/.ost) anywhere under root_dir. Returns
    (paths, truncated) - matches every other artifact-parser module's
    find_X_files() shape in this app."""
    found = []
    walked = 0
    max_walked = 40_000
    all_ext = _EML_EXTENSIONS + _MBOX_EXTENSIONS + _PST_EXTENSIONS
    for root, dirs, files in os.walk(root_dir):
        dirs[:] = [d for d in dirs if d not in _SCAN_SKIP_DIR_NAMES and not d.endswith(_SCAN_SKIP_DIR_SUFFIXES)]
        for fname in files:
            walked += 1
            if walked > max_walked:
                return found, True
            if fname.lower().endswith(all_ext):
                found.append(os.path.join(root, fname))
                if len(found) >= EMAIL_SCAN_MAX_CANDIDATES:
                    return found, True
    return found, False


def _body_preview(text):
    if not text:
        return ''
    stripped = _HTML_TAG_RE.sub(' ', text) if '<' in text and '>' in text else text
    stripped = ' '.join(stripped.split())
    return stripped[:EMAIL_BODY_PREVIEW_MAX_CHARS]


def _extract_body_and_attachments(msg):
    """Standard-library email.message.Message walk - prefers the first
    text/plain part, falls back to a tag-stripped text/html part, and
    counts real (non-inline, has-a-filename) attachments separately from
    the body parts themselves.

    Uses get_payload(decode=True) rather than the newer get_content() -
    a real bug caught live while verifying this module: mailbox.mbox()'s
    default factory returns a legacy email.message.Message (via its
    mailbox.mboxMessage subclass), which has no get_content() method at
    all (that's EmailMessage-only, the modern policy-based API this
    module's own parse_eml_file() opts into via policy=email.policy.
    default) - every mbox-sourced message's body silently came back empty,
    caught by AttributeError falling into this function's own try/except.
    get_payload(decode=True) works identically on both legacy Message and
    modern EmailMessage objects, so one code path now serves both
    parse_eml_file()'s and parse_mbox_file()'s message objects correctly."""
    body = ''
    attachment_count = 0

    def _part_text(part):
        try:
            raw = part.get_payload(decode=True)
        except Exception:
            return ''
        if raw is None:
            return ''
        if isinstance(raw, bytes):
            charset = part.get_content_charset() or 'utf-8'
            try:
                return raw.decode(charset, errors='replace')
            except (LookupError, TypeError):
                return raw.decode('utf-8', errors='replace')
        return str(raw)

    if msg.is_multipart():
        html_fallback = ''
        for part in msg.walk():
            if part.is_multipart():
                continue
            content_type = part.get_content_type()
            disposition = str(part.get('Content-Disposition', ''))
            if part.get_filename() or 'attachment' in disposition.lower():
                attachment_count += 1
                continue
            if content_type == 'text/plain' and not body:
                body = _part_text(part)
            elif content_type == 'text/html' and not html_fallback:
                html_fallback = _part_text(part)
        if not body:
            body = html_fallback
    else:
        body = _part_text(msg)
    return _body_preview(body), attachment_count


def _epoch_from_email_date(raw_date_header):
    if not raw_date_header:
        return None
    try:
        dt = email.utils.parsedate_to_datetime(raw_date_header)
        if dt is None:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except (TypeError, ValueError, OverflowError):
        return None


def _record_from_stdlib_message(msg, source_label):
    subject = str(msg.get('Subject', '') or '')
    sender = str(msg.get('From', '') or '')
    to = str(msg.get('To', '') or '')
    cc = str(msg.get('Cc', '') or '')
    body_preview, attachment_count = _extract_body_and_attachments(msg)
    return {
        "artifact_type": "email_message", "title": subject or "(no subject)", "url": "",
        "value": sender, "timestamp": _epoch_from_email_date(msg.get('Date')),
        "extra": {
            "to": to, "cc": cc, "body_preview": body_preview,
            "attachment_count": attachment_count, "source_format": source_label,
        },
    }


def parse_eml_file(path):
    """A single .eml file (one message) - best-effort, returns [] on any
    parse failure rather than raising, matching every other whole-folder
    scanner in this app."""
    try:
        with open(path, 'rb') as f:
            msg = email.message_from_binary_file(f, policy=email.policy.default)
        return [_record_from_stdlib_message(msg, "eml")]
    except Exception as e:
        print(f"Warning: could not parse .eml file {path}: {e}")
        return []


def parse_mbox_file(path):
    """An .mbox file (one-to-many messages, the classic Unix mailbox
    format) - mailbox.mbox() handles the 'From ' line-based message
    separator format internally, so this just iterates it."""
    records = []
    try:
        box = mailbox.mbox(path, factory=None)
        try:
            for i, msg in enumerate(box):
                if i >= EMAIL_MBOX_MAX_MESSAGES_PER_FILE:
                    break
                try:
                    # mailbox.mbox's own default factory returns a
                    # mailbox.mboxMessage, a real email.message.Message
                    # subclass - _extract_body_and_attachments() and every
                    # header lookup above work on it unchanged.
                    records.append(_record_from_stdlib_message(msg, "mbox"))
                except Exception:
                    continue
        finally:
            box.close()
    except Exception as e:
        print(f"Warning: could not parse .mbox file {path}: {e}")
    return records


def _pff_time_to_epoch(pff_datetime):
    """pypff's own get_X_time() accessors already return a native Python
    datetime (confirmed live) - no FILETIME/epoch math needed here, unlike
    core/registry_utils.py's raw-FILETIME fields."""
    if pff_datetime is None:
        return None
    try:
        dt = pff_datetime
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except (AttributeError, OverflowError, ValueError):
        return None


def _walk_pff_folder(folder, records, source_label):
    if len(records) >= EMAIL_PST_MAX_MESSAGES:
        return
    for i in range(folder.number_of_sub_messages):
        if len(records) >= EMAIL_PST_MAX_MESSAGES:
            return
        try:
            msg = folder.get_sub_message(i)
            subject = msg.get_subject() or ''
            sender = msg.get_sender_name() or ''
            ts = _pff_time_to_epoch(msg.get_delivery_time()) or _pff_time_to_epoch(msg.get_client_submit_time())
            body = msg.get_plain_text_body() or msg.get_html_body() or ''
            if isinstance(body, bytes):
                body = body.decode('utf-8', errors='ignore')
            records.append({
                "artifact_type": "email_message", "title": subject or "(no subject)", "url": "",
                "value": sender, "timestamp": ts,
                "extra": {
                    "to": "", "cc": "", "body_preview": _body_preview(body),
                    "attachment_count": msg.get_number_of_attachments(), "source_format": source_label,
                },
            })
        except Exception:
            continue
    for i in range(folder.number_of_sub_folders):
        if len(records) >= EMAIL_PST_MAX_MESSAGES:
            return
        try:
            _walk_pff_folder(folder.get_sub_folder(i), records, source_label)
        except Exception:
            continue


def parse_pst_file(path):
    """An Outlook .pst/.ost file - opens via pypff and recursively walks
    every folder's messages. Best-effort throughout: a corrupted/
    unrecognized file, or a single unreadable message deep in the tree,
    never aborts the whole parse - matches every other whole-folder
    scanner's tolerance in this app."""
    records = []
    try:
        import pypff
    except ImportError:
        print("Warning: libpff-python (pypff) is not installed - cannot parse PST/OST files.")
        return records
    try:
        f = pypff.file()
        f.open(path)
        try:
            root = f.get_root_folder()
            _walk_pff_folder(root, records, "pst")
        finally:
            f.close()
    except Exception as e:
        print(f"Warning: could not parse PST/OST file {path}: {e}")
    return records


def parse_email_file(path, filename=None):
    """Dispatches a candidate email-container file (matched by extension
    via find_email_files()) to the right parser."""
    name = (filename or os.path.basename(path)).lower()
    if name.endswith(_EML_EXTENSIONS):
        return parse_eml_file(path)
    if name.endswith(_MBOX_EXTENSIONS):
        return parse_mbox_file(path)
    if name.endswith(_PST_EXTENSIONS):
        return parse_pst_file(path)
    return []
