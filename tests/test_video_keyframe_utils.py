"""Tests for core/video_keyframe_utils.py. Mocks subprocess.run - no
genuine ffmpeg/ffprobe binary needed to test this module's own request-
shaping/response-handling/interval-math logic; ffmpeg's own real frame
extraction is an independently-tested, well-established real tool, not
this module's own risk."""
import json
import subprocess

import core.video_keyframe_utils as vku


class _FakeCompletedProcess:
    def __init__(self, returncode=0, stdout='', stderr=''):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_get_video_duration_seconds_parses_real_ffprobe_json(monkeypatch):
    def fake_run(cmd, **kw):
        assert cmd[0] == 'ffprobe'
        return _FakeCompletedProcess(returncode=0, stdout=json.dumps({"format": {"duration": "125.437000"}}))
    monkeypatch.setattr(subprocess, 'run', fake_run)
    duration, error = vku.get_video_duration_seconds('/mnt/case/video.mp4')
    assert error is None
    assert duration == 125.437


def test_get_video_duration_seconds_nonzero_exit_returns_error(monkeypatch):
    monkeypatch.setattr(subprocess, 'run', lambda cmd, **kw: _FakeCompletedProcess(returncode=1, stderr='Invalid data found'))
    duration, error = vku.get_video_duration_seconds('/mnt/case/notavideo.txt')
    assert duration is None
    assert 'Invalid data found' in error


def test_get_video_duration_seconds_malformed_json_returns_error(monkeypatch):
    monkeypatch.setattr(subprocess, 'run', lambda cmd, **kw: _FakeCompletedProcess(returncode=0, stdout='not json'))
    duration, error = vku.get_video_duration_seconds('/mnt/case/x.mp4')
    assert duration is None
    assert 'duration' in error.lower()


def test_get_video_duration_seconds_missing_binary_returns_clean_error(monkeypatch):
    def fake_run(cmd, **kw):
        raise FileNotFoundError()
    monkeypatch.setattr(subprocess, 'run', fake_run)
    duration, error = vku.get_video_duration_seconds('/mnt/case/x.mp4')
    assert duration is None
    assert 'not installed' in error


def test_generate_video_contact_sheet_success(tmp_path, monkeypatch):
    out_path = tmp_path / 'contact_sheet.jpg'
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        if cmd[0] == 'ffprobe':
            return _FakeCompletedProcess(returncode=0, stdout=json.dumps({"format": {"duration": "60.0"}}))
        # ffmpeg call - actually write a real stand-in output file, mirroring
        # what a real ffmpeg run would leave on disk.
        out_path.write_bytes(b'\xff\xd8\xff\xe0FAKEJPEG')
        return _FakeCompletedProcess(returncode=0)
    monkeypatch.setattr(subprocess, 'run', fake_run)

    frame_count, error = vku.generate_video_contact_sheet('/mnt/case/video.mp4', str(out_path))
    assert error is None
    assert frame_count == vku.CONTACT_SHEET_GRID_COLS * vku.CONTACT_SHEET_GRID_ROWS
    assert out_path.exists()
    # Confirm the real select+tile filter graph was actually constructed
    # with a sane interval (60s / 12 frames = 5s).
    ffmpeg_cmd = calls[1]
    vf_arg = ffmpeg_cmd[ffmpeg_cmd.index('-vf') + 1]
    assert 'tile=4x3' in vf_arg
    assert 'gte(t-prev_selected_t' in vf_arg


def test_generate_video_contact_sheet_propagates_duration_error(monkeypatch):
    monkeypatch.setattr(subprocess, 'run', lambda cmd, **kw: _FakeCompletedProcess(returncode=1, stderr='no such file'))
    frame_count, error = vku.generate_video_contact_sheet('/mnt/case/missing.mp4', '/tmp/out.jpg')
    assert frame_count is None
    assert error is not None


def test_generate_video_contact_sheet_ffmpeg_failure_after_successful_probe(tmp_path, monkeypatch):
    def fake_run(cmd, **kw):
        if cmd[0] == 'ffprobe':
            return _FakeCompletedProcess(returncode=0, stdout=json.dumps({"format": {"duration": "10.0"}}))
        return _FakeCompletedProcess(returncode=1, stderr='Unknown encoder')
    monkeypatch.setattr(subprocess, 'run', fake_run)
    frame_count, error = vku.generate_video_contact_sheet('/mnt/case/video.mp4', str(tmp_path / 'out.jpg'))
    assert frame_count is None
    assert 'Unknown encoder' in error


def test_is_video_candidate_file_recognizes_common_formats():
    assert vku.is_video_candidate_file('recording.MP4') is True
    assert vku.is_video_candidate_file('clip.mkv') is True
    assert vku.is_video_candidate_file('document.pdf') is False
