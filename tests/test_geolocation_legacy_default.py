"""tasks.md D16, decided 2026-11-20: Geolocation keeps its include-when-absent
default for callers that omit it, so existing non-UI callers' exports don't
change. This pins that decision."""
import pytest

pytest.importorskip("routes.reporting", reason="routes.reporting needs core.jobs, which imports POSIX-only pwd/fcntl")

from routes.reporting import LEGACY_SECTIONS_OFF_WHEN_UNSPECIFIED


def test_geolocation_stays_on_when_a_caller_omits_it():
    assert "geolocation" not in LEGACY_SECTIONS_OFF_WHEN_UNSPECIFIED
