"""Tests for core/ipa_utils.py's plist/mobileprovision-layer parsing - an
.ipa is a plain zip and Info.plist/embedded.mobileprovision's payload are
both real, standard plist format, all parsed via the stdlib `plistlib` -
zero third-party dependency, so real, valid hand-built .ipa fixtures can
be constructed and tested here directly (with run_macho=False, or letting
the optional Mach-O layer's own graceful "LIEF is not installed" fallback
fire naturally, both of which are also tested below). The Mach-O layer's
real, LIEF-dependent tests live in tests/test_ipa_utils_lief.py, gated by
a module-level pytest.importorskip."""
import plistlib
import zipfile

import core.ipa_utils as ipa


def _build_ipa(tmp_path, name, plist_data, mobileprovision_xml=None, executable_bytes=None,
                bundle_name='TestApp.app'):
    """Builds a real, valid, zipfile.ZipFile-openable .ipa matching Apple's
    real Payload/<AppName>.app/ packaging layout."""
    ipa_path = tmp_path / name
    with zipfile.ZipFile(ipa_path, 'w') as zf:
        zf.writestr(f'Payload/{bundle_name}/Info.plist', plistlib.dumps(plist_data))
        if mobileprovision_xml is not None:
            zf.writestr(f'Payload/{bundle_name}/embedded.mobileprovision', mobileprovision_xml)
        if executable_bytes is not None:
            exe_name = plist_data.get('CFBundleExecutable', 'TestApp')
            zf.writestr(f'Payload/{bundle_name}/{exe_name}', executable_bytes)
    return str(ipa_path)


_BASIC_PLIST = {
    'CFBundleIdentifier': 'com.example.testapp',
    'CFBundleDisplayName': 'Test App',
    'CFBundleShortVersionString': '1.2.3',
    'CFBundleVersion': '42',
    'MinimumOSVersion': '15.0',
    'CFBundleExecutable': 'TestApp',
    'NSCameraUsageDescription': 'Needs camera for QR scanning',
    'NSLocationWhenInUseUsageDescription': 'Needs location for maps',
}


def test_analyze_ipa_missing_file_returns_clean_error(tmp_path):
    result = ipa.analyze_ipa(str(tmp_path / 'does_not_exist.ipa'), run_macho=False)
    assert result['success'] is False
    assert 'Could not open' in result['error']


def test_analyze_ipa_not_a_zip_returns_clean_error(tmp_path):
    garbage = tmp_path / 'garbage.ipa'
    garbage.write_bytes(b'not a zip file at all')
    result = ipa.analyze_ipa(str(garbage), run_macho=False)
    assert result['success'] is False
    assert 'Could not open' in result['error']


def test_analyze_ipa_zip_with_no_payload_app_bundle_returns_clean_error(tmp_path):
    empty_zip = tmp_path / 'no_app.ipa'
    with zipfile.ZipFile(empty_zip, 'w') as zf:
        zf.writestr('README.txt', 'not a real ipa structure')
    result = ipa.analyze_ipa(str(empty_zip), run_macho=False)
    assert result['success'] is False
    assert 'No Payload' in result['error']


def test_analyze_ipa_parses_real_info_plist_correctly(tmp_path):
    path = _build_ipa(tmp_path, 'app.ipa', _BASIC_PLIST)
    result = ipa.analyze_ipa(path, run_macho=False)
    assert result['success'] is True
    assert result['error'] is None
    p = result['info_plist']
    assert p['bundle_id'] == 'com.example.testapp'
    assert p['app_name'] == 'Test App'
    assert p['version'] == '1.2.3'
    assert p['build'] == '42'
    assert p['min_os_version'] == '15.0'
    assert p['executable_name'] == 'TestApp'


def test_analyze_ipa_collects_usage_descriptions_separately():
    from core.ipa_utils import _USAGE_DESCRIPTION_RE
    assert _USAGE_DESCRIPTION_RE.search('NSCameraUsageDescription')
    assert _USAGE_DESCRIPTION_RE.search('NSLocationWhenInUseUsageDescription')
    assert not _USAGE_DESCRIPTION_RE.search('CFBundleIdentifier')


def test_analyze_ipa_usage_descriptions_appear_in_real_parsed_output(tmp_path):
    path = _build_ipa(tmp_path, 'app.ipa', _BASIC_PLIST)
    result = ipa.analyze_ipa(path, run_macho=False)
    usage = result['info_plist']['usage_descriptions']
    assert usage['NSCameraUsageDescription'] == 'Needs camera for QR scanning'
    assert usage['NSLocationWhenInUseUsageDescription'] == 'Needs location for maps'
    assert 'CFBundleIdentifier' not in usage


def test_analyze_ipa_falls_back_to_bundle_name_when_no_display_name(tmp_path):
    plist_data = dict(_BASIC_PLIST)
    del plist_data['CFBundleDisplayName']
    plist_data['CFBundleName'] = 'FallbackName'
    path = _build_ipa(tmp_path, 'app.ipa', plist_data)
    result = ipa.analyze_ipa(path, run_macho=False)
    assert result['info_plist']['app_name'] == 'FallbackName'


def test_analyze_ipa_with_no_embedded_mobileprovision_is_not_an_error(tmp_path):
    # A simulator build (or one never signed for a real device) has no
    # embedded.mobileprovision at all - a real, non-error state, not a
    # parse failure.
    path = _build_ipa(tmp_path, 'app.ipa', _BASIC_PLIST, mobileprovision_xml=None)
    result = ipa.analyze_ipa(path, run_macho=False)
    assert result['success'] is True
    assert result['mobileprovision'] is None


def test_analyze_ipa_parses_a_real_mobileprovision_plist_payload(tmp_path):
    # A real embedded.mobileprovision is a CMS/PKCS#7-signed blob whose
    # payload IS a plain plist - this module deliberately doesn't verify
    # the signature (byte-offset boundary extraction only), so a real
    # test fixture only needs the plist bytes embedded with a plausible
    # CMS-looking prefix/suffix around them, matching what the real byte-
    # offset regex actually looks for.
    mp_plist = plistlib.dumps({
        'AppIDName': 'Test App Provisioning',
        'TeamName': 'Example Forensics Lab',
        'TeamIdentifier': ['ABCDE12345'],
        'ProvisionedDevices': ['00008030-000AAA1122BB003E'],
        'Entitlements': {'application-identifier': 'ABCDE12345.com.example.testapp',
                          'get-task-allow': True},
    })
    fake_cms_wrapped = b'\x30\x82\x0a\x00-----CMS-SIGNATURE-BYTES-NOT-REAL-----' + mp_plist + b'\x00\x00-trailer-'
    path = _build_ipa(tmp_path, 'app.ipa', _BASIC_PLIST, mobileprovision_xml=fake_cms_wrapped)
    result = ipa.analyze_ipa(path, run_macho=False)
    assert result['success'] is True
    mp = result['mobileprovision']
    assert mp['app_id_name'] == 'Test App Provisioning'
    assert mp['team_name'] == 'Example Forensics Lab'
    assert mp['team_identifiers'] == ['ABCDE12345']
    assert mp['provisioned_devices'] == ['00008030-000AAA1122BB003E']
    assert mp['entitlements']['application-identifier'] == 'ABCDE12345.com.example.testapp'
    assert mp['entitlements']['get-task-allow'] is True


def test_analyze_ipa_mobileprovision_with_unparseable_plist_payload_reports_error_not_crash(tmp_path):
    # A real-looking <?xml ... </plist> boundary that isn't valid plist
    # content underneath - must report a clean per-field error, never
    # crash the whole analysis (the Info.plist layer already succeeded).
    fake_mp = b'<?xml version="1.0"?>not actually valid plist content</plist>'
    path = _build_ipa(tmp_path, 'app.ipa', _BASIC_PLIST, mobileprovision_xml=fake_mp)
    result = ipa.analyze_ipa(path, run_macho=False)
    assert result['success'] is True  # the overall analysis still succeeds
    assert 'error' in result['mobileprovision']


def test_analyze_ipa_with_run_macho_false_never_touches_macho_at_all(tmp_path):
    path = _build_ipa(tmp_path, 'app.ipa', _BASIC_PLIST, executable_bytes=b'\xfe\xed\xfa\xcf fake macho bytes')
    result = ipa.analyze_ipa(path, run_macho=False)
    assert result['macho'] is None
    assert result['macho_error'] is None


def test_analyze_ipa_macho_layer_failure_never_fails_the_whole_analysis(tmp_path):
    # With LIEF genuinely not installed on this dev machine, the macho
    # layer degrades gracefully - the plist-layer result must still come
    # back complete and correct regardless.
    path = _build_ipa(tmp_path, 'app.ipa', _BASIC_PLIST, executable_bytes=b'\xfe\xed\xfa\xcf fake macho bytes')
    result = ipa.analyze_ipa(path, run_macho=True)
    assert result['success'] is True
    assert result['info_plist']['bundle_id'] == 'com.example.testapp'
    assert result['macho'] is None
    assert result['macho_error'] is not None


def test_analyze_ipa_macho_layer_with_no_cfbundleexecutable_reports_a_clean_reason(tmp_path):
    plist_data = dict(_BASIC_PLIST)
    del plist_data['CFBundleExecutable']
    path = _build_ipa(tmp_path, 'app.ipa', plist_data)
    result = ipa.analyze_ipa(path, run_macho=True)
    assert result['success'] is True
    assert result['macho'] is None
    assert 'CFBundleExecutable' in result['macho_error']
