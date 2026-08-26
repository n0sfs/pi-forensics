"""core/crypto_artifacts.py - cryptocurrency wallet-FILE detection
(filename/path classifier only, not internal wallet-content parsing - see
the module's own docstring for why).

Pure stdlib, no optional pip dependency - no skip guard needed.
"""
import core.crypto_artifacts as ca


def test_find_wallet_dat_by_exact_basename(tmp_path):
    (tmp_path / "wallet.dat").write_bytes(b"fake berkeley db content")
    (tmp_path / "unrelated.dat").write_bytes(b"not a wallet")
    found, truncated = ca.find_crypto_wallet_files(str(tmp_path))
    names = {p.split('/')[-1].split('\\')[-1] for p in found}
    assert names == {"wallet.dat"}
    assert truncated is False


def test_find_ethereum_keystore_requires_keystore_parent_dir(tmp_path):
    keystore_dir = tmp_path / "keystore"
    keystore_dir.mkdir()
    (keystore_dir / "UTC--2026-01-01T00-00-00.000000000Z--abc123").write_text("{}")
    # Same filename shape sitting OUTSIDE a "keystore" folder must NOT match -
    # the parent-directory requirement is load-bearing, not decorative.
    (tmp_path / "UTC--not-in-keystore-dir").write_text("{}")
    found, truncated = ca.find_crypto_wallet_files(str(tmp_path))
    assert len(found) == 1
    assert "keystore" in found[0].replace("\\", "/")


def test_find_electrum_default_wallet_matches_by_name_anywhere(tmp_path):
    # "default_wallet" is a curated exact-basename match (a genuinely
    # Electrum-specific literal filename) - it matches regardless of
    # .electrum ancestry, same as wallet.dat/wallet.json do.
    (tmp_path / "default_wallet").write_text("fake electrum wallet")
    found, truncated = ca.find_crypto_wallet_files(str(tmp_path))
    assert len(found) == 1


def test_find_electrum_custom_named_wallet_needs_wallets_dir_under_electrum_path(tmp_path):
    # A user-renamed Electrum wallet file (not literally "default_wallet")
    # is only recognized via the path-shape check: sitting directly under a
    # "wallets" folder that itself has .electrum somewhere in its ancestry.
    electrum_wallets = tmp_path / ".electrum" / "wallets"
    electrum_wallets.mkdir(parents=True)
    (electrum_wallets / "my_custom_wallet_name").write_text("fake electrum wallet")
    # The identical filename sitting under an unrelated "wallets" folder
    # (no .electrum ancestor) must NOT match.
    other_wallets = tmp_path / "some_app" / "wallets"
    other_wallets.mkdir(parents=True)
    (other_wallets / "my_custom_wallet_name").write_text("unrelated")
    found, truncated = ca.find_crypto_wallet_files(str(tmp_path))
    assert len(found) == 1
    assert ".electrum" in found[0].replace("\\", "/")


def test_parse_wallet_file_is_detection_only_and_names_the_type(tmp_path):
    p = tmp_path / "wallet.dat"
    p.write_bytes(b"x" * 100)
    records = ca.parse_crypto_wallet_file(str(p))
    assert len(records) == 1
    r = records[0]
    assert r["artifact_type"] == "crypto_wallet_file"
    assert r["title"] == "wallet.dat"
    assert "Bitcoin Core" in r["value"]
    assert r["extra"]["file_size"] == 100
    assert r["timestamp"] is not None
    assert "not decrypted/parsed" in r["extra"]["note"]


def test_parse_wallet_file_uses_explicit_filename_over_temp_path_basename(tmp_path):
    # Mirrors every other parser module's parse_*_file(path, filename)
    # convention - the in-image route always passes the real in-image
    # entry name explicitly, since `path` there is a meaningless
    # temp-extracted filename.
    p = tmp_path / "some_temp_extracted_name"
    p.write_bytes(b"fake keystore content")
    records = ca.parse_crypto_wallet_file(str(p), filename="UTC--2026-01-01T00-00-00Z--abc")
    assert records[0]["title"] == "UTC--2026-01-01T00-00-00Z--abc"


def test_parse_wallet_file_returns_empty_list_on_stat_failure():
    records = ca.parse_crypto_wallet_file("/nonexistent/path/wallet.dat")
    assert records == []


def test_walk_caps_at_max_candidates(tmp_path):
    keystore_dir = tmp_path / "keystore"
    keystore_dir.mkdir()
    for i in range(ca.CRYPTO_WALLET_MAX_CANDIDATES + 5):
        (keystore_dir / f"UTC--fake-{i}").write_text("{}")
    found, truncated = ca.find_crypto_wallet_files(str(tmp_path))
    assert len(found) == ca.CRYPTO_WALLET_MAX_CANDIDATES
    assert truncated is True


def test_walk_skips_recovered_files_and_carving_tool_output_dirs(tmp_path):
    (tmp_path / "RECOVERED_FILES").mkdir()
    (tmp_path / "RECOVERED_FILES" / "wallet.dat").write_bytes(b"carved")
    (tmp_path / "case_photorec").mkdir()
    (tmp_path / "case_photorec" / "wallet.dat").write_bytes(b"carved")
    (tmp_path / "wallet.dat").write_bytes(b"real")
    found, truncated = ca.find_crypto_wallet_files(str(tmp_path))
    assert len(found) == 1
