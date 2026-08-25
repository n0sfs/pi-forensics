"""routes/reporting.py's _parse_kml_placemarks() - parses examiner-uploaded/
hand-edited/third-party .kml files (Geolocation export/import), not
necessarily ones this app generated itself. Previously used the bare stdlib
xml.etree.ElementTree, whose protection against billion-laughs/XXE-style
entity attacks depends entirely on whichever libexpat happens to be bundled
with the deployed Python - empirically confirmed already safe on the real
Pi's Python 3.13.5/libexpat 2.8.2 (2026-08-25), but that's an environmental
property this app doesn't control. Switched to defusedxml.ElementTree (a
drop-in replacement - ParseError is literally the same class, re-exported)
so the protection is deterministic regardless of the underlying system.

Skipped (not failed) on a non-POSIX dev machine: routes.reporting needs
core.jobs, which imports POSIX-only pwd/fcntl, matching every other
routes/*.py test in this suite.
"""
import pytest

pytest.importorskip("core.jobs", reason="routes.reporting needs core.jobs, which imports POSIX-only pwd/fcntl")

import routes.reporting as reporting

_VALID_KML = """<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2">
<Document>
<Placemark>
<name>Test Point</name>
<description>A real placemark</description>
<Point><coordinates>-122.4194,37.7749,0</coordinates></Point>
</Placemark>
</Document>
</kml>
"""

_BILLION_LAUGHS_KML = """<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<kml><Placemark><name>&lol3;</name><Point><coordinates>1,2,3</coordinates></Point></Placemark></kml>
"""

_XXE_KML = """<?xml version="1.0"?>
<!DOCTYPE kml [
 <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<kml><Placemark><description>&xxe;</description><Point><coordinates>1,2,3</coordinates></Point></Placemark></kml>
"""


def test_parses_a_real_valid_kml_placemark():
    placemarks = reporting._parse_kml_placemarks(_VALID_KML)
    assert len(placemarks) == 1
    assert placemarks[0]["name"] == "Test Point"
    assert placemarks[0]["lat"] == 37.7749
    assert placemarks[0]["lon"] == -122.4194


def test_rejects_billion_laughs_payload_returns_empty_list_not_raise():
    # Must not raise, must not hang, must not return any placemark built
    # from the expanded entity content.
    placemarks = reporting._parse_kml_placemarks(_BILLION_LAUGHS_KML)
    assert placemarks == []


def test_rejects_xxe_payload_returns_empty_list_and_never_leaks_file_content():
    placemarks = reporting._parse_kml_placemarks(_XXE_KML)
    assert placemarks == []
    # Belt-and-suspenders: even if some future change made this "succeed"
    # instead of rejecting outright, real /etc/passwd content must never
    # show up in the result.
    assert not any('root:' in str(p) for p in placemarks)


def test_rejects_genuinely_malformed_xml_returns_empty_list():
    placemarks = reporting._parse_kml_placemarks("<kml><this is not valid xml")
    assert placemarks == []


def test_rejects_empty_string_returns_empty_list():
    assert reporting._parse_kml_placemarks("") == []
