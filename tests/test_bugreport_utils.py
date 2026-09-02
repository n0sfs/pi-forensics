"""Tests for core/bugreport_utils.py's _make_json_safe() - pure stdlib
logic, no dumpstate-py import needed, tested fully here regardless of
environment. parse_bugreport() itself needs the real dumpstate-py package
(confirmed live-installable on this station's ARM64 venv, not guessed -
see the module's own docstring) - those tests live in a separate file,
tests/test_bugreport_utils_dumpstate.py, gated by a module-level
pytest.importorskip (matching this project's own established convention
for a whole file's worth of real-package-dependent tests - see
test_prefetch_utils.py/test_srum_utils.py) so they SKIP entirely on a dev
machine without the package and run for real on the Pi, where it is."""
import core.bugreport_utils as br

# --- _make_json_safe() - pure, no third-party dependency ---

def test_make_json_safe_passes_through_plain_scalars():
    assert br._make_json_safe(None) is None
    assert br._make_json_safe(True) is True
    assert br._make_json_safe(42) == 42
    assert br._make_json_safe(3.14) == 3.14
    assert br._make_json_safe("plain string") == "plain string"


def test_make_json_safe_decodes_bytes_values():
    assert br._make_json_safe(b'hello') == 'hello'


def test_make_json_safe_decodes_bytes_with_invalid_utf8_via_replace():
    # Real device-sourced content isn't guaranteed valid UTF-8 - this must
    # never raise, matching this app's own established convention
    # elsewhere (e.g. core/linux_artifacts.py's auth.log handling).
    result = br._make_json_safe(b'\xff\xfe not valid utf-8')
    assert isinstance(result, str)
    assert 'not valid utf-8' in result


def test_make_json_safe_recurses_into_nested_dicts_and_lists():
    nested = {"a": [1, {"b": b'nested bytes'}, "c"], "d": (4, 5)}
    result = br._make_json_safe(nested)
    assert result == {"a": [1, {"b": "nested bytes"}, "c"], "d": [4, 5]}


def test_make_json_safe_decodes_bytes_dict_keys_too():
    # Confirmed live: some of dumpstate-py's own dicts have bytes KEYS,
    # not just bytes values (e.g. a DumpstateHeader's uptime dict).
    result = br._make_json_safe({b'days': 1, b'hours': 2})
    assert result == {'days': 1, 'hours': 2}
    assert all(isinstance(k, str) for k in result)


def test_make_json_safe_falls_back_to_str_for_unrecognized_objects():
    # Confirmed live: dumpstate-py's own internal RawData helper class is a
    # plain, non-dataclass object that can slip through unconverted -
    # falling back to str() rather than passing it through unchanged is
    # what keeps json.dumps() from crashing downstream.
    class _NotJsonSafe:
        def __str__(self):
            return "RawData(0x1234)"
    result = br._make_json_safe(_NotJsonSafe())
    assert result == "RawData(0x1234)"


def test_make_json_safe_tuple_becomes_a_list():
    assert br._make_json_safe((1, 2, 3)) == [1, 2, 3]
