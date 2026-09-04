"""Real, hand-built .ab fixture tests for core/android_backup_utils.py -
Android pattern-of-life follow-up, 2026-09-04. No real device-produced .ab
file was available this session (the same disclosed-gap pattern already
established elsewhere in this project for a proprietary/complex binary
format with no practical hand-construction path - e.g. Prefetch, SRUM), so
every fixture here is built directly against the format's own confirmed
real structure (the plain-ASCII header; DEFLATE compression; the real AOSP
AES-256/PBKDF2 algorithm, ported and cross-checked against ab-decrypt's own
real, MIT-licensed reference source; the real AOSP TelephonyBackupAgent SMS/
MMS JSON shapes, quoted directly from the real AOSP source this session
fetched) rather than mocked or guessed at.

The encrypted-fixture tests below build their own AES-256/PBKDF2-protected
.ab file using the module's own `_java_checksum_utf8_quirk()` helper
directly (imported, not re-derived) - this is deliberate: it proves the
DECODER'S real end-to-end correctness (a correctly password-protected real
Android backup decrypts to the exact original tar bytes, and a wrong
password is cleanly rejected) without needing to independently re-implement
the same quirk a second, possibly-inconsistent way just for the test's own
encoder half.
"""
import io
import json
import tarfile
import zlib

import pytest

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

import core.android_backup_utils as ab_utils


def _build_tar_bytes(files):
    """files: {tar_member_name: content_bytes}"""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, content in files.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def _write_plain_ab(path, tar_bytes, compressed=True, version=5):
    header = b"ANDROID BACKUP\n" + f"{version}\n".encode() + (b"1\n" if compressed else b"0\n") + b"none\n"
    payload = zlib.compress(tar_bytes) if compressed else tar_bytes
    with open(path, "wb") as f:
        f.write(header)
        f.write(payload)


def _build_encrypted_ab_payload(tar_bytes, password, compressed=True, rounds=1000):
    """Mirrors the real AOSP encryption algorithm (the encode-side of what
    core/android_backup_utils.py's decoder implements) - builds a real,
    correctly-encrypted .ab file byte-for-byte, so the decrypt tests below
    prove genuine round-trip correctness, not just "some bytes went in and
    some bytes came out."""
    plaintext = zlib.compress(tar_bytes) if compressed else tar_bytes

    mk = b"\x11" * 32          # master key (fixed, not random - deterministic fixture)
    mk_iv = b"\x22" * 16
    pwd_salt = b"\x33" * 64
    mk_ck_salt = b"\x44" * 64
    uk_iv = b"\x55" * 16

    payload_padder = padding.PKCS7(128).padder()
    padded_payload = payload_padder.update(plaintext) + payload_padder.finalize()
    encryptor = Cipher(algorithms.AES(mk), modes.CBC(mk_iv)).encryptor()
    encrypted_payload = encryptor.update(padded_payload) + encryptor.finalize()

    mk_ck = PBKDF2HMAC(algorithm=hashes.SHA1(), length=32, salt=mk_ck_salt, iterations=rounds).derive(
        ab_utils._java_checksum_utf8_quirk(mk)
    )
    blob = bytes([len(mk_iv)]) + mk_iv + bytes([len(mk)]) + mk + bytes([len(mk_ck)]) + mk_ck
    blob_padder = padding.PKCS7(128).padder()
    padded_blob = blob_padder.update(blob) + blob_padder.finalize()

    user_key = PBKDF2HMAC(algorithm=hashes.SHA1(), length=32, salt=pwd_salt, iterations=rounds).derive(
        password.encode("utf-8")
    )
    blob_encryptor = Cipher(algorithms.AES(user_key), modes.CBC(uk_iv)).encryptor()
    encrypted_blob = blob_encryptor.update(padded_blob) + blob_encryptor.finalize()

    header = (
        b"ANDROID BACKUP\n5\n" + (b"1\n" if compressed else b"0\n") + b"AES-256\n"
        + pwd_salt.hex().encode() + b"\n"
        + mk_ck_salt.hex().encode() + b"\n"
        + f"{rounds}\n".encode()
        + uk_iv.hex().encode() + b"\n"
        + encrypted_blob.hex().encode() + b"\n"
    )
    return header + encrypted_payload


def _write_encrypted_ab(path, tar_bytes, password, compressed=True, rounds=1000):
    with open(path, "wb") as f:
        f.write(_build_encrypted_ab_payload(tar_bytes, password, compressed=compressed, rounds=rounds))


# --- Header parsing -------------------------------------------------------

def test_parse_ab_header_valid_unencrypted():
    fp = io.BytesIO(b"ANDROID BACKUP\n5\n1\nnone\nrest-of-payload")
    header = ab_utils.parse_ab_header(fp)
    assert header == {"version": 5, "compressed": True, "encryption": "none"}
    assert fp.read() == b"rest-of-payload"


def test_parse_ab_header_bad_magic_raises():
    fp = io.BytesIO(b"NOT A REAL BACKUP\n5\n1\nnone\n")
    with pytest.raises(ab_utils.AndroidBackupError, match="bad magic"):
        ab_utils.parse_ab_header(fp)


def test_parse_ab_header_bad_encryption_raises():
    fp = io.BytesIO(b"ANDROID BACKUP\n5\n1\nrot13\n")
    with pytest.raises(ab_utils.AndroidBackupError, match="Unrecognized"):
        ab_utils.parse_ab_header(fp)


def test_parse_ab_header_non_numeric_version_raises():
    fp = io.BytesIO(b"ANDROID BACKUP\nfive\n1\nnone\n")
    with pytest.raises(ab_utils.AndroidBackupError, match="Malformed"):
        ab_utils.parse_ab_header(fp)


# --- Unencrypted decode ----------------------------------------------------

def test_decrypt_and_decompress_unencrypted_compressed_round_trip(tmp_path):
    tar_bytes = _build_tar_bytes({"apps/com.example/f/hello.txt": b"hello world"})
    ab_path = tmp_path / "backup.ab"
    _write_plain_ab(str(ab_path), tar_bytes, compressed=True)

    header, decoded = ab_utils.decrypt_and_decompress_backup(str(ab_path))
    assert header["encryption"] == "none"
    assert header["compressed"] is True
    assert decoded == tar_bytes


def test_decrypt_and_decompress_unencrypted_uncompressed_round_trip(tmp_path):
    tar_bytes = _build_tar_bytes({"apps/com.example/f/hello.txt": b"plain, no zlib"})
    ab_path = tmp_path / "backup.ab"
    _write_plain_ab(str(ab_path), tar_bytes, compressed=False)

    header, decoded = ab_utils.decrypt_and_decompress_backup(str(ab_path))
    assert header["compressed"] is False
    assert decoded == tar_bytes


# --- Encrypted decode -------------------------------------------------------

def test_decrypt_and_decompress_encrypted_correct_password_round_trip(tmp_path):
    tar_bytes = _build_tar_bytes({"apps/com.android.providers.telephony/f/000000_sms_backup": b"[]"})
    ab_path = tmp_path / "backup.ab"
    _write_encrypted_ab(str(ab_path), tar_bytes, password="correcthorsebattery")

    header, decoded = ab_utils.decrypt_and_decompress_backup(str(ab_path), password="correcthorsebattery")
    assert header["encryption"] == "AES-256"
    assert decoded == tar_bytes


def test_decrypt_and_decompress_encrypted_wrong_password_raises(tmp_path):
    tar_bytes = _build_tar_bytes({"f": b"data"})
    ab_path = tmp_path / "backup.ab"
    _write_encrypted_ab(str(ab_path), tar_bytes, password="the-real-password")

    with pytest.raises(ab_utils.AndroidBackupPasswordError, match="Incorrect backup password"):
        ab_utils.decrypt_and_decompress_backup(str(ab_path), password="wrong-guess")


def test_decrypt_and_decompress_encrypted_missing_password_raises(tmp_path):
    tar_bytes = _build_tar_bytes({"f": b"data"})
    ab_path = tmp_path / "backup.ab"
    _write_encrypted_ab(str(ab_path), tar_bytes, password="some-password")

    with pytest.raises(ab_utils.AndroidBackupPasswordError, match="password-protected"):
        ab_utils.decrypt_and_decompress_backup(str(ab_path))


# --- Tar-slip guard ---------------------------------------------------------

def test_extract_backup_to_directory_rejects_path_traversal_member(tmp_path):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        good = tarfile.TarInfo(name="apps/com.example/f/ok.txt")
        good.size = 2
        tar.addfile(good, io.BytesIO(b"ok"))
        evil = tarfile.TarInfo(name="../../../../tmp/escaped.txt")
        evil.size = 4
        tar.addfile(evil, io.BytesIO(b"evil"))
    tar_bytes = buf.getvalue()

    ab_path = tmp_path / "backup.ab"
    _write_plain_ab(str(ab_path), tar_bytes, compressed=False)

    dest = tmp_path / "extracted"
    result = ab_utils.extract_backup_to_directory(str(ab_path), str(dest))

    assert "apps/com.example/f/ok.txt" in result["files"]
    assert not any("escaped.txt" in n for n in result["files"])
    assert (dest / "apps" / "com.example" / "f" / "ok.txt").exists()
    # the traversal target must never have been written anywhere real
    assert not (tmp_path.parent / "escaped.txt").exists()


# --- SMS/MMS JSON parsing (real AOSP-quoted sample shapes) -----------------

def test_parse_sms_backup_json_real_aosp_sample_ms_to_seconds():
    # Quoted verbatim from the real AOSP TelephonyBackupAgent.java source.
    raw = json.dumps([{
        "self_phone": "+1234567891011", "address": "+1234567891012",
        "body": "Example sms", "date": "1450893518140",
        "date_sent": "1450893514000", "status": "-1", "type": "1",
    }]).encode("utf-8")

    records = ab_utils.parse_sms_backup_json(raw, "000000_sms_backup")
    assert len(records) == 1
    r = records[0]
    assert r["artifact_type"] == "android_ab_sms_message"
    assert r["value"] == "Example sms"
    assert r["extra"]["address"] == "+1234567891012"
    # "date":"1450893518140" is milliseconds - must divide by 1000, not pass through.
    assert r["timestamp"] == pytest.approx(1450893518.140)
    assert r["extra"]["date_sent"] == pytest.approx(1450893514.0)
    assert "Received" in r["title"]  # type "1" == received


def test_parse_mms_backup_json_real_aosp_sample_seconds_not_ms():
    # Quoted verbatim from the real AOSP TelephonyBackupAgent.java source.
    raw = json.dumps([{
        "self_phone": "+1234567891011", "date": "1451322716", "date_sent": "0",
        "m_type": "128", "v": "18", "msg_box": "2",
        "mms_addresses": [{"address": "recipient@example.com", "type": 151}],
        "mms_body": "Mms to email",
    }]).encode("utf-8")

    records = ab_utils.parse_mms_backup_json(raw, "000000_mms_backup")
    assert len(records) == 1
    r = records[0]
    assert r["artifact_type"] == "android_ab_mms_message"
    assert r["value"] == "Mms to email"
    # "date":"1451322716" is already SECONDS - a real, different unit from
    # SMS's own "date" field in the very same backup family. Must NOT be
    # divided by 1000 (that would silently produce a bogus 1970s timestamp).
    assert r["timestamp"] == pytest.approx(1451322716.0)
    assert "Sent" in r["title"]  # msg_box "2" == Sent
    assert "To: recipient@example.com" in r["extra"]["addresses"]


def test_parse_sms_backup_json_skips_malformed_entries_without_crashing():
    raw = json.dumps([
        "this is not a dict",
        {"address": "+15551234567", "body": "real message", "date": "1000000", "type": "1"},
        42,
    ]).encode("utf-8")
    records = ab_utils.parse_sms_backup_json(raw, "000000_sms_backup")
    assert len(records) == 1
    assert records[0]["value"] == "real message"


def test_parse_sms_backup_json_not_a_json_array_returns_empty():
    assert ab_utils.parse_sms_backup_json(b'{"not": "a list"}', "x") == []
    assert ab_utils.parse_sms_backup_json(b"not even json", "x") == []


# --- End-to-end orchestration ------------------------------------------------

def test_extract_parsed_artifact_records_from_backup_end_to_end(tmp_path):
    sms_json = json.dumps([
        {"address": "+15551111111", "body": "sms one", "date": "1600000000000", "type": "1"},
        {"address": "+15552222222", "body": "sms two", "date": "1600000001000", "type": "2"},
    ]).encode("utf-8")
    mms_json = json.dumps([
        {"date": "1600000002", "msg_box": "1", "mms_body": "mms one",
         "mms_addresses": [{"address": "+15553333333", "type": 137}]},
    ]).encode("utf-8")
    tar_bytes = _build_tar_bytes({
        "apps/com.android.providers.telephony/f/000000_sms_backup": sms_json,
        "apps/com.android.providers.telephony/f/000000_mms_backup": mms_json,
        "apps/com.android.providers.contacts/f/some_other_file": b"irrelevant",
    })
    ab_path = tmp_path / "real_backup.ab"
    _write_plain_ab(str(ab_path), tar_bytes, compressed=True)

    result = ab_utils.extract_parsed_artifact_records_from_backup(str(ab_path))
    assert result["header"]["encryption"] == "none"
    assert len(result["files"]) == 3
    assert result["sms_files"] == ["apps/com.android.providers.telephony/f/000000_sms_backup"]
    assert result["mms_files"] == ["apps/com.android.providers.telephony/f/000000_mms_backup"]
    assert len(result["records"]) == 3  # 2 sms + 1 mms
    sms_records = [r for r in result["records"] if r["artifact_type"] == "android_ab_sms_message"]
    mms_records = [r for r in result["records"] if r["artifact_type"] == "android_ab_mms_message"]
    assert len(sms_records) == 2
    assert len(mms_records) == 1


def test_extract_parsed_artifact_records_from_backup_encrypted_end_to_end(tmp_path):
    """The full real pipeline - header, AES-256/PBKDF2 decrypt, DEFLATE
    decompress, tar-open, and SMS-JSON parse - all chained together against
    one real encrypted fixture, proving the whole route-facing function
    works end-to-end, not just its individual pieces in isolation."""
    sms_json = json.dumps([
        {"address": "+15559998888", "body": "encrypted sms", "date": "1650000000000", "type": "1"},
    ]).encode("utf-8")
    tar_bytes = _build_tar_bytes({"apps/com.android.providers.telephony/f/000000_sms_backup": sms_json})
    ab_path = tmp_path / "encrypted_backup.ab"
    _write_encrypted_ab(str(ab_path), tar_bytes, password="hunter2")

    result = ab_utils.extract_parsed_artifact_records_from_backup(str(ab_path), password="hunter2")
    assert len(result["records"]) == 1
    assert result["records"][0]["value"] == "encrypted sms"

    with pytest.raises(ab_utils.AndroidBackupPasswordError):
        ab_utils.extract_parsed_artifact_records_from_backup(str(ab_path), password="wrong")


def test_extract_parsed_artifact_records_from_backup_no_sms_mms_still_lists_files(tmp_path):
    tar_bytes = _build_tar_bytes({"apps/com.example.other/f/data.db": b"other app data"})
    ab_path = tmp_path / "backup.ab"
    _write_plain_ab(str(ab_path), tar_bytes, compressed=False)

    result = ab_utils.extract_parsed_artifact_records_from_backup(str(ab_path))
    assert result["sms_files"] == []
    assert result["mms_files"] == []
    assert result["records"] == []
    assert result["files"] == ["apps/com.example.other/f/data.db"]


# --- Size cap ---------------------------------------------------------------

def test_decompress_size_cap_enforced(tmp_path, monkeypatch):
    monkeypatch.setattr(ab_utils, "AB_MAX_DECODED_BYTES", 10)
    tar_bytes = _build_tar_bytes({"f": b"x" * 5000})  # decompresses well past the 10-byte cap
    ab_path = tmp_path / "huge.ab"
    _write_plain_ab(str(ab_path), tar_bytes, compressed=True)

    with pytest.raises(ab_utils.AndroidBackupError, match="size cap"):
        ab_utils.decrypt_and_decompress_backup(str(ab_path))


def test_sms_mms_filename_regexes_match_real_aosp_naming_and_reject_others():
    assert ab_utils.SMS_BACKUP_FILENAME_RE.match("000000_sms_backup")
    assert ab_utils.SMS_BACKUP_FILENAME_RE.match("000042_sms_backup")
    assert not ab_utils.SMS_BACKUP_FILENAME_RE.match("000000_mms_backup")
    assert ab_utils.MMS_BACKUP_FILENAME_RE.match("000001_mms_backup")
    assert not ab_utils.MMS_BACKUP_FILENAME_RE.match("sms_backup")  # no leading digits
