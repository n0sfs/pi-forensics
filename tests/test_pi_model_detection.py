"""core/config.py's detect_pi_model()/usb_port_diagram_supported()
(2026-09-05) - the station's own real board-model detection, gating
Drive Management's USB port diagram to the one board (Raspberry Pi 4)
this app's core/paths.py port-color mapping was actually empirically
verified against. Fails closed for any other board (a different real Pi
model, an undetected board, a plain dev machine with no device tree at
all) rather than showing a diagram that might be wrong for it.
"""
import core.config as config


def test_detect_pi_model_returns_the_real_file_content_with_the_trailing_nul_stripped(monkeypatch, tmp_path):
    # /proc/device-tree/model files are always NUL-terminated - a real,
    # confirmed gotcha (live on the deployed Pi 4B: "Raspberry Pi 4 Model
    # B Rev 1.5\x00") that must not leak into the returned string.
    model_file = tmp_path / "model"
    model_file.write_bytes(b"Raspberry Pi 4 Model B Rev 1.5\x00")
    monkeypatch.setattr(config, "PI_MODEL_FILE", str(model_file))
    assert config.detect_pi_model() == "Raspberry Pi 4 Model B Rev 1.5"


def test_detect_pi_model_returns_none_when_the_file_is_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "PI_MODEL_FILE", str(tmp_path / "does_not_exist"))
    assert config.detect_pi_model() is None


def test_detect_pi_model_returns_none_for_an_empty_file(monkeypatch, tmp_path):
    model_file = tmp_path / "model"
    model_file.write_bytes(b"")
    monkeypatch.setattr(config, "PI_MODEL_FILE", str(model_file))
    assert config.detect_pi_model() is None


def test_usb_port_diagram_supported_true_for_a_real_pi4b_model_string(monkeypatch, tmp_path):
    model_file = tmp_path / "model"
    model_file.write_bytes(b"Raspberry Pi 4 Model B Rev 1.5\x00")
    monkeypatch.setattr(config, "PI_MODEL_FILE", str(model_file))
    assert config.usb_port_diagram_supported() is True


def test_usb_port_diagram_supported_false_for_a_different_real_pi_model(monkeypatch, tmp_path):
    # A different Pi model has a genuinely different physical port layout -
    # this must not silently apply the Pi 4B-specific mapping to it.
    model_file = tmp_path / "model"
    model_file.write_bytes(b"Raspberry Pi 5 Model B Rev 1.0\x00")
    monkeypatch.setattr(config, "PI_MODEL_FILE", str(model_file))
    assert config.usb_port_diagram_supported() is False


def test_usb_port_diagram_supported_false_when_no_pi_is_detected_at_all(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "PI_MODEL_FILE", str(tmp_path / "does_not_exist"))
    assert config.usb_port_diagram_supported() is False
