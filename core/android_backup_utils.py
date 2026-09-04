"""Android Backup Format (.ab) decoder - header parsing, DEFLATE decompression,
AES-256/PBKDF2 decryption, and tar extraction, plus SMS/MMS artifact indexing.

Built 2026-09-04, Android pattern-of-life follow-up: after the user pointed
out a rooted phone (needed for the app's existing native mmssms.db parser,
core/android_artifacts.py) will be rare in real casework, this closes the gap
for the much more common case - this app's own Mobile Forensics "Backup"
acquisition mode (routes/mobile.py, execution_worker_android()) already runs
`adb backup -apk -shared -all -f output.ab` and produces a real .ab file, but
nothing in this codebase has ever parsed it until now.

Format, confirmed via the real AOSP source (PerformAdbBackupTask.java, the
implementation ab-decrypt's own docstring cites) and the real ab-decrypt
(github.com/joernheissler/ab-decrypt, MIT) / android_backup (PyPI, Apache-2.0,
unmaintained since 2018, PyCrypto-based) reference implementations, both read
directly and compared before writing this: a plain ASCII header (magic line
"ANDROID BACKUP", version 1-5, a compression flag 0/1, and an encryption
algorithm line - "none" or "AES-256") followed by a DEFLATE-compressed tar
archive, additionally AES-256-CBC-encrypted (key derived from a user password
via PBKDF2-SHA1, with an inner encrypted master-key blob whose own checksum is
independently PBKDF2-SHA1-verified) when a password was set on-device at
backup time. This module's AES/PBKDF2 logic is a direct port of ab-decrypt's
own `derive_aes_256_key()`/`decrypt_android_backup()` (MIT-licensed, credited
above) - re-implemented here against this app's own dependency (`cryptography`,
already used elsewhere in this codebase, e.g. routes/settings.py's config
backup/restore feature) rather than added as a new pip dependency, and wired
into this app's own parsed_artifacts indexing pipeline instead of ab-decrypt's
own CLI-only, decrypt-to-a-file design.

A real, load-bearing detail worth stating plainly: the real Android
implementation uses SHA-1 (not SHA-256) for both PBKDF2 derivations (the user
key, and the master-key checksum) - this is not a security choice being made
here, it's what the fixed, real on-device Android implementation actually
does, and changing it would silently break decryption against every real
backup.

Real, confirmed SMS/MMS backup content shape, from the real AOSP source
(TelephonyBackupAgent.java, packages/providers/TelephonyProvider) fetched and
read directly rather than guessed: SMS/MMS content is written into the backup
tar as one or more JSON-array files per message type, named
"%06d_sms_backup"/"%06d_mms_backup" (e.g. "000000_sms_backup"), split every
1000 messages (mMaxMsgPerFile) regardless of directory prefix - this module
therefore matches on basename suffix only, not the exact tar path, the same
defensive-matching-by-suffix convention already used elsewhere in this
codebase (Recycle Bin's $I* files, Prefetch's filename variants).

Real, confirmed SMS sample (quoted from the real AOSP source):
    {"self_phone":"+1234567891011","address":"+1234567891012",
     "body":"Example sms","date":"1450893518140",
     "date_sent":"1450893514000","status":"-1","type":"1"}
"date"/"date_sent" are 13-digit decimal strings - milliseconds since epoch.

Real, confirmed MMS sample (quoted from the same source):
    {"self_phone":"+1234567891011","date":"1451322716","date_sent":"0",
     "m_type":"128","v":"18","msg_box":"2",
     "mms_addresses":[...],"mms_body":"Mms to email"}
"date"/"date_sent" here are 10-digit decimal strings - SECONDS since epoch,
a genuinely different unit from SMS's own "date"/"date_sent" fields in the
very same backup file family - matching the "seconds, not ms" convention
already confirmed this session for MMS's native mmssms.db "date" column
(core/android_artifacts.py's android_mms_date_to_unix()), and easy to get
wrong if assumed to match SMS's own millisecond convention. "msg_box" is the
same folder-type integer Telephony.Mms uses (1=inbox, 2=sent, 3=drafts,
4=outbox); "mms_addresses" entries carry an address "type" using the same
PduHeaders address-type constants already confirmed and used in
core/android_artifacts.py's native MMS parser (137=FROM, 151/130/129=TO/CC/
BCC).
"""
import io
import json
import os
import re
import tarfile
import zlib

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

AB_MAGIC = b"ANDROID BACKUP"

# A malformed/hostile .ab could in principle claim an enormous decompressed
# size - this caps the in-memory tar buffer this module will ever build, the
# same "no silent unbounded reads" discipline already established elsewhere
# in this app (e.g. IMAGE_HASH_MAX_FILES, LOGICAL_ACQ_MAX_TOTAL_BYTES).
AB_MAX_DECODED_BYTES = 4 * 1024 * 1024 * 1024  # 4 GB

SMS_BACKUP_FILENAME_RE = re.compile(r"^\d+_sms_backup$")
MMS_BACKUP_FILENAME_RE = re.compile(r"^\d+_mms_backup$")

_MMS_ADDR_TYPE_LABELS = {137: "From", 151: "To", 130: "Cc", 129: "Bcc"}
_MMS_MSG_BOX_LABELS = {1: "Inbox", 2: "Sent", 3: "Drafts", 4: "Outbox"}


class AndroidBackupError(Exception):
    """Raised for a malformed header, an unsupported encryption algorithm,
    or (via AndroidBackupPasswordError below) a missing/wrong password -
    always a clean, examiner-facing message, never a raw traceback."""


class AndroidBackupPasswordError(AndroidBackupError):
    """Raised specifically when a password is required but missing, or the
    supplied password fails the real AOSP checksum verification - a route
    can catch this one specifically to prompt for (or re-prompt for) a
    password, distinct from every other AndroidBackupError."""


def parse_ab_header(fp):
    """Reads and validates the plain-ASCII .ab header, leaving fp positioned
    at the start of the (possibly compressed, possibly encrypted) payload.
    Returns {"version": int, "compressed": bool, "encryption": "none"|"AES-256"}.
    Raises AndroidBackupError on a bad magic line or an unrecognized
    encryption algorithm - never lets a malformed header reach the decoder
    below with a half-parsed state."""
    magic_line = fp.readline().rstrip(b"\n")
    if magic_line != AB_MAGIC:
        raise AndroidBackupError(
            "Not a valid Android Backup file (bad magic header) - is this a "
            "real .ab file produced by `adb backup`?"
        )
    try:
        version = int(fp.readline().strip())
        compressed_flag = int(fp.readline().strip())
    except ValueError as exc:
        raise AndroidBackupError("Malformed .ab header (version/compression field not numeric).") from exc
    encryption = fp.readline().strip().decode("ascii", errors="replace")
    if encryption not in ("none", "AES-256"):
        raise AndroidBackupError(f"Unrecognized .ab encryption algorithm: {encryption!r}")
    return {"version": version, "compressed": bool(compressed_flag), "encryption": encryption}


def _java_checksum_utf8_quirk(buf):
    """Reproduces a real, confirmed quirk in Android's own PBKDF2 master-key
    checksum: the raw master-key bytes are first reinterpreted as if each
    byte were a UTF-16 code unit (with any byte >= 0x80 shifted into the
    0xFF00 "fullwidth forms" range, matching Java's default-charset string
    construction on a byte array), then re-encoded as UTF-8, before being fed
    into the checksum's own PBKDF2 call - NOT applied to the master key
    itself, only to this one checksum-verification step. Ported from
    ab-decrypt's utf8_encode() (MIT-licensed, see the module docstring)."""
    return "".join(chr(b if b < 0x80 else b + 0xFF00) for b in buf).encode("utf-8")


def _derive_aes256_key_iv(password_bytes, pwd_salt, mk_ck_salt, rounds, uk_iv, mk_blob):
    """Derives the real master AES key/IV from a user-supplied password and
    the .ab header's own encryption parameters. Raises
    AndroidBackupPasswordError on a checksum mismatch (wrong password) -
    every other failure here is a genuine format/parsing problem, not a
    password problem, and is left to surface as a plain AndroidBackupError
    from its own call site instead."""
    # A wrong password doesn't just fail the checksum comparison below - it
    # first produces effectively-random bytes when the master-key blob is
    # decrypted, which very reliably fails PKCS7 unpadding outright (a real
    # bug caught live by this module's own test suite: the first version of
    # this function let that ValueError escape as a raw, un-translated
    # exception instead of the intended AndroidBackupPasswordError). Every
    # failure in this whole derive-decrypt-unpad-verify sequence means the
    # same thing to an examiner - wrong password - so the entire block is
    # wrapped in one try/except and re-raised consistently, the same pattern
    # ab-decrypt's own reference implementation uses at its own call site.
    try:
        user_key = PBKDF2HMAC(algorithm=hashes.SHA1(), length=32, salt=pwd_salt, iterations=rounds).derive(password_bytes)

        cipher = Cipher(algorithms.AES(user_key), modes.CBC(uk_iv))
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(128).unpadder()
        blob = bytearray(unpadder.update(decryptor.update(mk_blob) + decryptor.finalize()) + unpadder.finalize())

        mk_iv_len = blob[0]
        mk_iv = bytes(blob[1:mk_iv_len + 1])
        del blob[:mk_iv_len + 1]

        mk_len = blob[0]
        mk = bytes(blob[1:mk_len + 1])
        del blob[:mk_len + 1]

        mk_ck_len = blob[0]
        if len(blob) - 1 != mk_ck_len:
            raise AndroidBackupPasswordError("Incorrect backup password (malformed master-key blob).")
        stored_checksum = bytes(blob[1:])

        computed_checksum = PBKDF2HMAC(
            algorithm=hashes.SHA1(), length=mk_ck_len, salt=mk_ck_salt, iterations=rounds
        ).derive(_java_checksum_utf8_quirk(mk))
    except AndroidBackupPasswordError:
        raise
    except (ValueError, IndexError) as exc:
        raise AndroidBackupPasswordError("Incorrect backup password.") from exc

    if stored_checksum != computed_checksum:
        raise AndroidBackupPasswordError("Incorrect backup password (checksum verification failed).")

    return mk, mk_iv


def _read_hex_line(fp):
    return bytes.fromhex(fp.readline().strip().decode("ascii"))


def decrypt_and_decompress_backup(path, password=None):
    """Opens a real .ab file, validates its header, decrypts (if AES-256
    encrypted - requires `password`, raises AndroidBackupPasswordError if
    missing or wrong) and decompresses (if flagged), and returns the full
    tar archive as raw bytes, capped at AB_MAX_DECODED_BYTES. Callers get a
    real tarfile.TarFile by wrapping the result in io.BytesIO()."""
    with open(path, "rb") as fp:
        header = parse_ab_header(fp)

        payload = fp
        if header["encryption"] == "AES-256":
            if not password:
                raise AndroidBackupPasswordError("This backup is password-protected - supply the backup password.")
            pwd_salt = _read_hex_line(fp)
            mk_ck_salt = _read_hex_line(fp)
            try:
                rounds = int(fp.readline().strip())
            except ValueError as exc:
                raise AndroidBackupError("Malformed .ab encryption header (PBKDF2 round count not numeric).") from exc
            uk_iv = _read_hex_line(fp)
            mk_blob = _read_hex_line(fp)

            key, iv = _derive_aes256_key_iv(password.encode("utf-8"), pwd_salt, mk_ck_salt, rounds, uk_iv, mk_blob)

            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            unpadder = padding.PKCS7(128).unpadder()
            decrypted = bytearray()
            for chunk in iter(lambda: fp.read(65536), b""):
                decrypted.extend(decryptor.update(chunk))
                if len(decrypted) > AB_MAX_DECODED_BYTES:
                    raise AndroidBackupError("Decrypted .ab payload exceeds the size cap - refusing to continue.")
            decrypted.extend(decryptor.finalize())
            decrypted = unpadder.update(bytes(decrypted)) + unpadder.finalize()
            payload = io.BytesIO(decrypted)

        if header["compressed"]:
            decompressor = zlib.decompressobj()
            out = bytearray()
            for chunk in iter(lambda: payload.read(65536), b""):
                out.extend(decompressor.decompress(chunk))
                if len(out) > AB_MAX_DECODED_BYTES:
                    raise AndroidBackupError("Decompressed .ab payload exceeds the size cap - refusing to continue.")
            out.extend(decompressor.flush())
            return header, bytes(out)

        raw = payload.read()
        if len(raw) > AB_MAX_DECODED_BYTES:
            raise AndroidBackupError(".ab payload exceeds the size cap - refusing to continue.")
        return header, raw


def _is_within_directory(directory, target):
    """Real tar-slip guard (the tar-format equivalent of the zip-slip guard
    already established for Google Takeout's own archive import,
    core/takeout_utils.py's _safe_extract_zip()) - confirms a tar member's
    resolved extraction path stays inside the intended destination directory
    before it's ever written, since Python's tarfile.extractall() does not
    sandbox this by default on every supported Python version."""
    abs_directory = os.path.realpath(directory)
    abs_target = os.path.realpath(target)
    return os.path.commonpath([abs_directory, abs_target]) == abs_directory


def extract_backup_to_directory(path, destination_dir, password=None):
    """Full extraction: decrypt+decompress, then safely extract every tar
    member into destination_dir. Returns {"header":, "files": [names...]}."""
    header, tar_bytes = decrypt_and_decompress_backup(path, password=password)
    os.makedirs(destination_dir, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:") as tar:
        safe_members = [
            m for m in tar.getmembers()
            if _is_within_directory(destination_dir, os.path.join(destination_dir, m.name))
        ]
        # filter='data' (Python 3.12+, present on both this app's dev
        # machine and the deployed station's real venv) is stdlib's own
        # second, independent layer of extraction hardening (strips device
        # files, absolute/traversal paths, etc.) - layered on top of, not a
        # replacement for, the explicit _is_within_directory() guard above.
        tar.extractall(path=destination_dir, members=safe_members, filter="data")
    return {"header": header, "files": [m.name for m in safe_members]}


def _to_float(raw):
    try:
        return float(raw)
    except (TypeError, ValueError):
        return None


def _ab_sms_date_to_unix(raw_ms_str):
    """SMS backup 'date'/'date_sent' - confirmed milliseconds since epoch."""
    val = _to_float(raw_ms_str)
    return val / 1000.0 if val else None


def _ab_mms_date_to_unix(raw_sec_str):
    """MMS backup 'date'/'date_sent' - confirmed SECONDS since epoch, NOT
    milliseconds like SMS's own date fields in the same backup family."""
    val = _to_float(raw_sec_str)
    return val if val else None


def parse_sms_backup_json(raw_bytes, source_path):
    """Parses one *_sms_backup JSON-array file into artifact records. Never
    raises on a malformed individual message - skips it and continues, so
    one bad entry in an otherwise-valid file can't lose the rest."""
    records = []
    try:
        messages = json.loads(raw_bytes.decode("utf-8", errors="replace"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return records
    if not isinstance(messages, list):
        return records
    for msg in messages:
        if not isinstance(msg, dict):
            continue
        address = msg.get("address") or "(unknown)"
        body = msg.get("body") or ""
        type_int = msg.get("type")
        direction = {"1": "Received", "2": "Sent"}.get(str(type_int), f"Type {type_int}")
        title = f"SMS ({direction}): {address}"
        records.append({
            "artifact_type": "android_ab_sms_message",
            "title": title,
            "url": None,
            "value": body,
            "timestamp": _ab_sms_date_to_unix(msg.get("date")),
            "extra": {
                "address": address,
                "self_phone": msg.get("self_phone"),
                "date_sent": _ab_sms_date_to_unix(msg.get("date_sent")),
                "type": type_int,
                "status": msg.get("status"),
                "source_file": source_path,
            },
        })
    return records


def parse_mms_backup_json(raw_bytes, source_path):
    """Parses one *_mms_backup JSON-array file into artifact records. Same
    resilient-per-message parsing as parse_sms_backup_json()."""
    records = []
    try:
        messages = json.loads(raw_bytes.decode("utf-8", errors="replace"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return records
    if not isinstance(messages, list):
        return records
    for msg in messages:
        if not isinstance(msg, dict):
            continue
        box_int = msg.get("msg_box")
        try:
            box_label = _MMS_MSG_BOX_LABELS.get(int(box_int), f"Box {box_int}")
        except (TypeError, ValueError):
            box_label = f"Box {box_int}"

        addresses = msg.get("mms_addresses") or []
        addr_parts = []
        if isinstance(addresses, list):
            for a in addresses:
                if not isinstance(a, dict):
                    continue
                try:
                    label = _MMS_ADDR_TYPE_LABELS.get(int(a.get("type")), "Addr")
                except (TypeError, ValueError):
                    label = "Addr"
                addr_val = a.get("address") or "?"
                addr_parts.append(f"{label}: {addr_val}")
        addr_summary = "; ".join(addr_parts) if addr_parts else "(no addresses)"

        body = msg.get("mms_body") or ""
        title = f"MMS ({box_label}): {addr_summary}"
        records.append({
            "artifact_type": "android_ab_mms_message",
            "title": title,
            "url": None,
            "value": body,
            "timestamp": _ab_mms_date_to_unix(msg.get("date")),
            "extra": {
                "addresses": addr_parts,
                "self_phone": msg.get("self_phone"),
                "date_sent": _ab_mms_date_to_unix(msg.get("date_sent")),
                "msg_box": box_int,
                "m_type": msg.get("m_type"),
                "source_file": source_path,
            },
        })
    return records


def extract_parsed_artifact_records_from_backup(path, password=None):
    """Top-level orchestration this app's routes call: decrypt+decompress a
    real .ab file, list every tar member, and parse every *_sms_backup/
    *_mms_backup file directly from the in-memory tar (no disk extraction
    needed for this indexing path). Returns
    {"header":, "files": [names...], "sms_files": [...], "mms_files": [...],
     "records": [...]}. Raises AndroidBackupError/AndroidBackupPasswordError
    on a real format/password problem - the caller (a Flask route) is
    expected to catch these and turn them into a clean 400."""
    header, tar_bytes = decrypt_and_decompress_backup(path, password=password)
    records = []
    all_names = []
    sms_files = []
    mms_files = []
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:") as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            all_names.append(member.name)
            basename = os.path.basename(member.name)
            if SMS_BACKUP_FILENAME_RE.match(basename):
                sms_files.append(member.name)
                fobj = tar.extractfile(member)
                if fobj is not None:
                    records.extend(parse_sms_backup_json(fobj.read(), member.name))
            elif MMS_BACKUP_FILENAME_RE.match(basename):
                mms_files.append(member.name)
                fobj = tar.extractfile(member)
                if fobj is not None:
                    records.extend(parse_mms_backup_json(fobj.read(), member.name))

    return {
        "header": header,
        "files": all_names,
        "sms_files": sms_files,
        "mms_files": mms_files,
        "records": records,
    }
