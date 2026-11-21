"""Redaction at report export (2026-11-21)."""
import json
import os

import pytest

pytest.importorskip("core.jobs", reason="routes need core.jobs, which imports POSIX-only pwd/fcntl")

from core.redaction import Redactor, RedactionError
from tests.test_fixed_report_templates_2026_11_21 import SHA, client, EVENTS  # noqa: F401
import routes.reporting as reporting


# --- the Redactor itself -------------------------------------------------

def test_terms_and_patterns():
    r = Redactor(["John Smith", "Acme"], emails=True, phones=True, cards=True)
    out = r("Contact john@acme.co.uk or +1 (555) 123-4567, card 4111 1111 1111 1111. JOHN SMITH of Acme.")
    assert out == "Contact [REDACTED] or [REDACTED], card [REDACTED]. [REDACTED] of [REDACTED]."
    assert r.count == 5


@pytest.mark.parametrize("text", [
    "sha256 daa817c5a148c184aa7a83a168fb93499080b97f620b55db236d61a61cbaa162",
    "md5 177f65d3e450c1a7eab056861192eb3d",
    "2026-11-21 22:18:35  1,573 files  192.168.86.210  /dev/sda  S6PNNX0T123456  160.0 GiB",
    "epoch ms 1700000000000, not a card 1234567890123456 (fails Luhn)",
])
def test_hashes_dates_ips_and_counters_survive(text):
    r = Redactor(emails=True, phones=True, cards=True)
    assert r(text) == text and r.count == 0


def test_bad_specs():
    assert Redactor.from_request(None) is None
    assert Redactor.from_request({"terms": ["", "  "]}) is None
    with pytest.raises(RedactionError):
        Redactor.from_request({"terms": ["x"]})
    with pytest.raises(RedactionError):
        Redactor.from_request({"terms": [f"t{i:03d}" for i in range(201)]})
    assert Redactor.from_request({"terms": "Alice\nBob"}).terms == ["Alice", "Bob"]


def test_html_document_redacts_text_and_attributes_not_markup():
    r = Redactor(["Smith"])
    doc = '<p title="Smith file" class="Smith">Mr Smith &amp; Smith&#x27;s</p><script>var n="Smith";</script>'
    assert r.html_document(doc) == ('<p title="[REDACTED] file" class="Smith">Mr [REDACTED] &amp; '
                                    '[REDACTED]&#x27;s</p><script>var n="[REDACTED]";</script>')


# --- through the export route -------------------------------------------

def _case(evidence_root):
    folder = os.path.join(evidence_root, "2026-RED")
    os.makedirs(folder, exist_ok=True)
    report = os.path.join(folder, "2026-RED_case.json")
    events = [dict(EVENTS[0], case_metadata={"evidence_id": "ITEM-02", "notes": "Seized from Jane Doe"})] + EVENTS[1:]
    with open(report, "w") as f:
        json.dump({"schema_version": 1, "case_number": "2026-RED", "case_folder": folder, "case_status": "Open",
                   "events": events, "updated_at": "2026-01-01 00:00:00",
                   "executive_summary": "Jane Doe (jane.doe@example.com, 555-123-4567) paid with 4111-1111-1111-1111.",
                   "case_notes": [{"timestamp": "2026-11-20 10:00", "text": "Called Jane Doe."}]}, f)
    return folder, report


SPEC = {"terms": ["Jane Doe"], "emails": True, "phones": True, "cards": True}


@pytest.mark.parametrize("template", ["standard", "dfir", "police", "caseuco"])
def test_html_export_is_redacted(client, evidence_root, template):
    _, report = _case(evidence_root)
    res = client.post("/api/export_report", json={"report_path": report, "format": "html", "template": template,
                                                  "preview": True, "redaction": SPEC,
                                                  "sections": {"case_details": True, "executive_summary": True}})
    assert res.status_code == 200, res.data[:300]
    body = res.data.decode()
    for leaked in ("Jane Doe", "jane.doe@example.com", "555-123-4567", "4111-1111-1111-1111"):
        assert leaked not in body, (template, leaked)
    assert "REDACTED COPY" in body and SHA in body
    assert int(res.headers["X-Report-Redactions"]) >= 1


def test_pdf_export_draws_no_redacted_text_and_logs_custody(client, evidence_root, monkeypatch):
    folder, report = _case(evidence_root)
    from reportlab.pdfgen import canvas
    drawn = []
    real_draw = canvas.Canvas.drawString

    def recording(self, x, y, text, *a, **k):
        drawn.append(str(text))
        return real_draw(self, x, y, text, *a, **k)

    monkeypatch.setattr(canvas.Canvas, "drawString", recording)
    logged = []
    monkeypatch.setattr(reporting, "log_chain_of_custody", lambda action, details, **k: logged.append((action, details)))
    res = client.post("/api/export_report", json={"report_path": report, "format": "pdf", "template": "dfir",
                                                  "redaction": SPEC})
    assert res.status_code == 200 and res.data.startswith(b"%PDF")
    assert res.headers["X-Report-Filename"].endswith("_REDACTED.pdf")
    text = "\n".join(drawn)
    assert "REDACTED COPY" in text and "[REDACTED]" in text
    for leaked in ("Jane Doe", "jane.doe@example.com", "555-123-4567", "4111-1111-1111-1111"):
        assert leaked not in text
    assert reporting._ACTIVE_REDACTOR.get() is None
    exported = [d for a, d in logged if a == "report_exported"]
    assert exported and exported[0]["redaction"]["terms"] == 1
    assert "Jane Doe" not in json.dumps(exported)


def test_unredacted_export_unchanged(client, evidence_root):
    _, report = _case(evidence_root)
    res = client.post("/api/export_report", json={"report_path": report, "format": "html", "template": "dfir", "preview": True})
    body = res.data.decode()
    assert "Jane Doe" in body and "REDACTED COPY" not in body and "X-Report-Redactions" not in res.headers


def test_bad_redaction_request_is_refused(client, evidence_root):
    _, report = _case(evidence_root)
    res = client.post("/api/export_report", json={"report_path": report, "format": "html", "template": "dfir",
                                                  "preview": True, "redaction": {"terms": ["x"]}})
    assert res.status_code == 400 and "too short" in res.get_json()["error"]
