"""core/tsk_utils.py: an image that cannot be opened, a partition that holds no
readable filesystem, and a file that cannot be read in full - each used to
look exactly like an ordinary "nothing here" (2026-10-02).

Fakes stand in for pytsk3's objects - this is control flow, not pytsk3's own
accuracy. core.tsk_utils imports pytsk3 at module level, so this skips where
that is not installed (a dev machine) and runs on the Pi.
"""
import io

import pytest

tsk_utils = pytest.importorskip("core.tsk_utils", reason="core.tsk_utils needs pytsk3")


class _Meta:
    def __init__(self, size):
        self.size = size


class _Info:
    def __init__(self, size):
        self.meta = _Meta(size)


class _FakeFile:
    """read_random() returns data up to `readable` bytes, then nothing - a
    file whose recorded size runs past what the image actually holds."""

    def __init__(self, size, readable):
        self.info = _Info(size)
        self.readable = readable

    def read_random(self, offset, length):
        end = min(offset + length, self.readable)
        return b"x" * max(0, end - offset)


def test_a_full_read_returns_its_length():
    buf = io.BytesIO()
    assert tsk_utils._tsk_stream_file(_FakeFile(5000, 5000), buf.write) == 5000
    assert len(buf.getvalue()) == 5000


def test_a_short_read_raises_instead_of_passing_as_the_file():
    with pytest.raises(tsk_utils.TskShortRead):
        tsk_utils._tsk_stream_file(_FakeFile(5000, 1200), io.BytesIO().write)


def test_a_preview_can_ask_for_what_could_be_read():
    buf = io.BytesIO()
    assert tsk_utils._tsk_stream_file(_FakeFile(5000, 1200), buf.write, allow_short=True) == 1200


def test_a_cap_below_the_size_is_not_a_short_read():
    buf = io.BytesIO()
    assert tsk_utils._tsk_stream_file(_FakeFile(5000, 5000), buf.write, max_bytes=100) == 100


def test_an_image_that_cannot_be_opened_is_not_an_image_with_no_filesystem(tmp_path):
    with pytest.raises(tsk_utils.ImageUnreadable):
        tsk_utils._tsk_resolve_filesystems(str(tmp_path / "missing.dd"))


def test_classify_reports_an_unopenable_image_instead_of_guessing(tmp_path):
    result = tsk_utils.classify_image_profile(str(tmp_path / "missing.dd"))
    assert result["profile"] == "unknown"
    assert "could not be opened" in result["error"]


class _Part:
    def __init__(self, start, desc, flags):
        self.start = start
        self.desc = desc.encode()
        self.flags = flags


def test_a_partition_without_a_readable_filesystem_is_listed_not_dropped(monkeypatch):
    alloc = tsk_utils.pytsk3.TSK_VS_PART_FLAG_ALLOC
    parts = [_Part(0, "Unallocated", tsk_utils.pytsk3.TSK_VS_PART_FLAG_UNALLOC),
             _Part(2048, "EFI system partition", alloc),
             _Part(206848, "Microsoft reserved partition", alloc),
             _Part(239616, "Basic data partition", alloc)]
    monkeypatch.setattr(tsk_utils.pytsk3, "Img_Info", lambda path: object())
    monkeypatch.setattr(tsk_utils.pytsk3, "Volume_Info", lambda img: parts)

    def open_fs(path, offset):
        if offset == 206848:
            raise IOError("Cannot determine file system type")
        return object()

    monkeypatch.setattr(tsk_utils, "_tsk_open_fs", open_fs)
    skipped = []
    filesystems = tsk_utils._tsk_resolve_filesystems("disk.dd", skipped=skipped)
    assert [f["offset"] for f in filesystems] == [2048, 239616]
    assert skipped == [{"offset": 206848, "label": "Microsoft reserved partition",
                        "error": "Cannot determine file system type"}]
    # A caller that passes no list keeps the old answer.
    assert len(tsk_utils._tsk_resolve_filesystems("disk.dd")) == 2
