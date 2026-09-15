"""_tsk_walk()'s own directory and depth caps, and the fact that they REPORT.

Both caps used to stop the walk in silence. Depth 25 is the one that bites in
practice: deeply nested real paths (node_modules trees, mail stores, per-user
cache hierarchies) were simply never reached, so their files were absent from
search results and from the Evidence Timeline with no disclosure anywhere. That
is worse than the per-source budget, which at least sets a truncated flag.

The `stats` parameter added 2026-09-15 lets a caller tell. These tests use a
fake filesystem object rather than a real image - the recursion and the caps
are pure control flow, and building a nested test image to exercise them would
test pytsk3 rather than this code.

core.tsk_utils imports pytsk3 at module level, so this skips where that is not
installed (a dev machine) and runs on the Pi.
"""
import pytest

tsk_utils = pytest.importorskip("core.tsk_utils", reason="core.tsk_utils needs pytsk3")


class _FakeFs:
    """A filesystem shaped as a chain of directories, each containing one
    subdirectory and one file, `depth` levels deep."""

    def __init__(self, depth=40, fanout=1):
        self.depth = depth
        self.fanout = fanout


def _install_fake_listdir(monkeypatch, depth, fanout=1):
    """Replaces _tsk_list_dir so the walk sees a predictable tree.

    Inode number doubles as the level, which keeps the fake trivial: level N
    contains `fanout` directories at level N+1 plus one file.
    """
    def fake_list_dir(fs, inode_num):
        level = 0 if inode_num is None else int(inode_num)
        if level >= depth:
            return [{"name": f"leaf{level}.txt", "inode": level * 1000 + 1,
                     "is_dir": False, "deleted": False, "is_virtual": False}]
        entries = []
        for i in range(fanout):
            entries.append({"name": f"dir{level}_{i}", "inode": level + 1,
                            "is_dir": True, "deleted": False, "is_virtual": False})
        entries.append({"name": f"file{level}.txt", "inode": level * 1000 + 2,
                        "is_dir": False, "deleted": False, "is_virtual": False})
        return entries

    monkeypatch.setattr(tsk_utils, "_tsk_list_dir", fake_list_dir)


def test_stats_reports_nothing_capped_on_a_shallow_tree(monkeypatch):
    _install_fake_listdir(monkeypatch, depth=3)
    stats = {}
    list(tsk_utils._tsk_walk(_FakeFs(), start_inode_num=0, stats=stats))
    assert stats["depth_capped"] is False
    assert stats["dirs_capped"] is False
    assert stats["dirs_visited"] > 0


def test_stats_reports_the_depth_cap_when_it_bites(monkeypatch):
    """The real-world case: a path nested deeper than the limit. Files below
    it are absent, and the caller must be able to say so."""
    _install_fake_listdir(monkeypatch, depth=100)
    stats = {}
    list(tsk_utils._tsk_walk(_FakeFs(), start_inode_num=0, max_depth=5, stats=stats))
    assert stats["depth_capped"] is True


def test_stats_reports_the_directory_cap_when_it_bites(monkeypatch):
    _install_fake_listdir(monkeypatch, depth=100, fanout=3)
    stats = {}
    list(tsk_utils._tsk_walk(_FakeFs(), start_inode_num=0, max_dirs=10, stats=stats))
    assert stats["dirs_capped"] is True


def test_a_caller_that_passes_no_stats_still_works(monkeypatch):
    """Every existing call site passes no stats - the parameter must be purely
    additive, not a behaviour change."""
    _install_fake_listdir(monkeypatch, depth=4)
    entries = list(tsk_utils._tsk_walk(_FakeFs(), start_inode_num=0))
    assert entries, "the walk yielded nothing"
    assert all(isinstance(path, str) for _entry, path in entries)


def test_the_walk_still_stops_at_the_caps(monkeypatch):
    """The caps are a guard against reused-inode loops on live evidence -
    reporting them must not have made them advisory."""
    _install_fake_listdir(monkeypatch, depth=1000)
    shallow = list(tsk_utils._tsk_walk(_FakeFs(), start_inode_num=0, max_depth=3))
    deep = list(tsk_utils._tsk_walk(_FakeFs(), start_inode_num=0, max_depth=8))
    assert len(shallow) < len(deep)
