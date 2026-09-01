"""Tests for core/ocr_utils.py. Mocks subprocess.run (no genuine tesseract
binary needed to test this module's own request-shaping/response-handling
logic) - the real, installed tesseract CLI's own OCR accuracy is not this
module's own risk, it's a well-established, independently-tested real
tool; what this module owns is correctly invoking it and handling its
real success/failure/timeout/missing-binary outcomes."""
import subprocess

import pytest

import core.ocr_utils as ocr


class _FakeCompletedProcess:
    def __init__(self, returncode=0, stdout='', stderr=''):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_run_ocr_on_image_returns_extracted_text_on_success(tmp_path, monkeypatch):
    img = tmp_path / 'evidence.png'
    img.write_bytes(b'\x89PNG\r\n\x1a\n')  # a minimal, not-a-real-PNG stand-in - subprocess is mocked anyway

    def fake_run(cmd, **kwargs):
        assert cmd == ['tesseract', str(img), 'stdout']
        return _FakeCompletedProcess(returncode=0, stdout='Confidential Report\nCase #2026-01\n')
    monkeypatch.setattr(subprocess, 'run', fake_run)

    text, error = ocr.run_ocr_on_image(str(img))
    assert error is None
    assert text == 'Confidential Report\nCase #2026-01'


def test_run_ocr_on_image_no_text_found_is_success_not_error(tmp_path, monkeypatch):
    img = tmp_path / 'blank.png'
    img.write_bytes(b'x')
    monkeypatch.setattr(subprocess, 'run', lambda cmd, **kw: _FakeCompletedProcess(returncode=0, stdout='   \n  '))
    text, error = ocr.run_ocr_on_image(str(img))
    assert error is None
    assert text == ''  # genuinely no text - a real, meaningful result, not a failure


def test_run_ocr_on_image_nonzero_exit_returns_error(tmp_path, monkeypatch):
    img = tmp_path / 'corrupt.png'
    img.write_bytes(b'x')
    monkeypatch.setattr(subprocess, 'run', lambda cmd, **kw: _FakeCompletedProcess(returncode=1, stderr='Error reading image file'))
    text, error = ocr.run_ocr_on_image(str(img))
    assert text is None
    assert 'Error reading image file' in error


def test_run_ocr_on_image_missing_binary_returns_clean_error(tmp_path, monkeypatch):
    img = tmp_path / 'x.png'
    img.write_bytes(b'x')
    def fake_run(cmd, **kw):
        raise FileNotFoundError()
    monkeypatch.setattr(subprocess, 'run', fake_run)
    text, error = ocr.run_ocr_on_image(str(img))
    assert text is None
    assert 'not installed' in error


def test_run_ocr_on_image_timeout_returns_clean_error(tmp_path, monkeypatch):
    img = tmp_path / 'x.png'
    img.write_bytes(b'x')
    def fake_run(cmd, **kw):
        raise subprocess.TimeoutExpired(cmd, kw.get('timeout', 90))
    monkeypatch.setattr(subprocess, 'run', fake_run)
    text, error = ocr.run_ocr_on_image(str(img))
    assert text is None
    assert 'timed out' in error


def test_run_ocr_on_image_missing_file_returns_clean_error(tmp_path):
    text, error = ocr.run_ocr_on_image(str(tmp_path / 'nonexistent.png'))
    assert text is None
    assert 'not found' in error.lower()


def test_run_ocr_on_image_truncates_long_output(tmp_path, monkeypatch):
    img = tmp_path / 'x.png'
    img.write_bytes(b'x')
    long_text = 'A' * (ocr.OCR_MAX_OUTPUT_CHARS + 500)
    monkeypatch.setattr(subprocess, 'run', lambda cmd, **kw: _FakeCompletedProcess(returncode=0, stdout=long_text))
    text, error = ocr.run_ocr_on_image(str(img))
    assert error is None
    assert 'truncated' in text
    assert len(text) < len(long_text)


def test_is_ocr_candidate_image_recognizes_common_formats():
    assert ocr.is_ocr_candidate_image('screenshot.PNG') is True
    assert ocr.is_ocr_candidate_image('scan.tiff') is True
    assert ocr.is_ocr_candidate_image('document.pdf') is False
    assert ocr.is_ocr_candidate_image('notes.txt') is False
