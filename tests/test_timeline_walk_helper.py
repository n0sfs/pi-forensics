"""_walk_files_with_stat() - the scandir walk behind the folder timeline
(2026-09-20).

Replaces os.walk + os.lstat. It must be behaviourally identical to what it
replaced, because the folder timeline is evidence: top-down, symlinked
directories not followed, unreadable directories skipped rather than raised,
and the stat returned must be the file's OWN metadata rather than a followed
symlink target.

Skipped (not failed) on a non-POSIX dev machine: routes.reporting needs
core.jobs, which imports POSIX-only pwd/fcntl.
"""
import os

import pytest

reporting = pytest.importorskip(
    "routes.reporting", reason="routes.reporting needs core.jobs, which imports POSIX-only pwd/fcntl")


def _build_tree(root):
    os.makedirs(os.path.join(root, "a", "b", "c"))
    os.makedirs(os.path.join(root, "d"))
    for rel in ("top.txt", "a/one.txt", "a/b/two.txt", "a/b/c/three.txt", "d/four.txt"):
        p = os.path.join(root, rel.replace("/", os.sep))
        with open(p, "w") as f:
            f.write(rel)
    return root


def test_finds_every_file_at_every_depth(tmp_path):
    root = _build_tree(str(tmp_path))
    found = {os.path.relpath(p, root).replace(os.sep, "/")
             for p, _ in reporting._walk_files_with_stat(root)}
    assert found == {"top.txt", "a/one.txt", "a/b/two.txt", "a/b/c/three.txt", "d/four.txt"}


def test_matches_os_walk_exactly(tmp_path):
    """The behaviour contract stated plainly: the replacement must see the same
    set of files the old os.walk pass did."""
    root = _build_tree(str(tmp_path))
    old = set()
    for dirpath, _dirs, files in os.walk(root):
        for f in files:
            old.add(os.path.join(dirpath, f))
    new = {p for p, _ in reporting._walk_files_with_stat(root)}
    assert new == old


def test_returns_usable_stat_for_each_file(tmp_path):
    root = _build_tree(str(tmp_path))
    for path, st in reporting._walk_files_with_stat(root):
        assert st.st_mtime > 0
        assert st.st_size == len(open(path).read())


def test_empty_directory_yields_nothing(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    assert list(reporting._walk_files_with_stat(str(empty))) == []


def test_missing_root_is_skipped_not_raised(tmp_path):
    """os.walk's default onerror=None swallows this; so must the replacement,
    or a vanished acquisition folder would abort an entire case timeline."""
    assert list(reporting._walk_files_with_stat(str(tmp_path / "nope"))) == []


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink semantics")
def test_symlinked_directory_is_not_followed(tmp_path):
    """os.walk(followlinks=False) treats a symlinked directory as something not
    to descend into. Following one could walk the same bytes twice, or escape
    the acquisition folder entirely."""
    root = str(tmp_path / "root")
    os.makedirs(os.path.join(root, "real"))
    with open(os.path.join(root, "real", "inside.txt"), "w") as f:
        f.write("x")
    os.symlink(os.path.join(root, "real"), os.path.join(root, "link"))

    found = {os.path.relpath(p, root).replace(os.sep, "/")
             for p, _ in reporting._walk_files_with_stat(root)}
    assert "real/inside.txt" in found
    assert "link/inside.txt" not in found, "must not descend through the symlink"


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink semantics")
def test_symlinked_file_reports_its_own_metadata(tmp_path):
    """lstat semantics, not stat. A symlink's own metadata is the forensically
    correct thing to record - the target's timestamps belong to the target."""
    root = str(tmp_path / "root")
    os.makedirs(root)
    target = os.path.join(root, "target.txt")
    with open(target, "w") as f:
        f.write("some real content here")
    link = os.path.join(root, "alias.txt")
    os.symlink(target, link)

    stats = {os.path.basename(p): st for p, st in reporting._walk_files_with_stat(root)}
    assert "alias.txt" in stats
    assert stats["alias.txt"].st_size != stats["target.txt"].st_size, \
        "a followed symlink would report the target's size"


@pytest.mark.skipif(os.name == "nt", reason="POSIX directory permissions")
def test_unreadable_subdirectory_is_skipped_not_raised(tmp_path):
    root = str(tmp_path / "root")
    os.makedirs(os.path.join(root, "open"))
    locked = os.path.join(root, "locked")
    os.makedirs(locked)
    with open(os.path.join(root, "open", "ok.txt"), "w") as f:
        f.write("x")
    os.chmod(locked, 0o000)
    try:
        found = {os.path.relpath(p, root).replace(os.sep, "/")
                 for p, _ in reporting._walk_files_with_stat(root)}
        assert "open/ok.txt" in found
    finally:
        os.chmod(locked, 0o755)
