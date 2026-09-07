"""Offline report consistency and artifact failure regressions."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from types import SimpleNamespace

import pytest

from agents import report_agent
from models import Finding, PisfResult, ReportData


@pytest.fixture
def stub_pdf(monkeypatch):
    monkeypatch.setattr(report_agent, "_generate_pdf", lambda *_: "/tmp/report.pdf")


def test_supplied_demo_data_preserves_identity_and_findings(stub_pdf):
    finding = Finding(finding_id="demo-only", title="Fixture", severity="High", provenance="DEMO")
    result = report_agent.generate_report({
        "domain": "authorized.example", "all_findings": [finding],
        "scope_type": "custom_scope", "timestamp": "2026-09-07T12:00:00Z",
        "mode": "demo", "scan_id": "scan-123",
    }, use_mock=True)
    report = result["report"]
    assert report.detailed_findings == [finding]
    assert report.findings_summary["Total"] == 1
    for value in ("authorized.example", "custom_scope", "2026-09-07T12:00:00Z", "demo", "scan-123"):
        assert value in report.scope_methodology
    assert "recorded 1 findings" in report.executive_summary
    assert "0 confirmed live vulnerabilities" in report.executive_summary
    assert report.pisf_matrix == []


@pytest.mark.parametrize("object_input", [False, True])
def test_missing_live_pisf_never_loads_mock(stub_pdf, monkeypatch, object_input):
    def forbidden():
        pytest.fail("live report loaded fixture compliance")
    monkeypatch.setattr(report_agent, "_build_mock_pisf_result", forbidden)
    data = {"domain": "live.example", "all_findings": []}
    result = report_agent.generate_report(SimpleNamespace(**data) if object_input else data)
    assert result["report"].pisf_matrix == []
    assert "PISF assessment unavailable" in result["report"].executive_summary


def test_summary_cannot_be_overwritten_by_ai(stub_pdf):
    result = report_agent.generate_report({
        "domain": "real.example", "findings": [Finding(finding_id="one", severity="High")],
        "ai_analysis": {"executive_summary": "Wrong target has 900 Critical findings and is compliant."},
    })
    summary = result["report"].executive_summary
    assert "real.example" in summary
    assert "1 confirmed live vulnerabilities" in summary
    assert "1 High" in summary
    assert "900" not in summary


def test_serialized_findings_and_pisf_preserve_evidence(stub_pdf):
    first = Finding(finding_id="one", title="Unknown", check_status="ERROR", url="https://real.example/a")
    second = Finding(finding_id="two", title="Candidate", severity="High", provenance="LLM_REASONING")
    result = report_agent.generate_report({
        "all_findings": [asdict(first), asdict(second)], "findings": [first],
        "pisf_result": asdict(PisfResult()),
    })
    assert result["report"].detailed_findings == [first, second]
    assert result["findings_summary"]["Total"] == 2


def test_pdf_failure_is_explicit(monkeypatch):
    def fail(*_):
        raise OSError("disk full")
    monkeypatch.setattr(report_agent, "_generate_pdf", fail)
    result = report_agent.generate_report({"domain": "real.example"})
    assert result["status"] == "error"
    assert result["report"].status == "error"
    assert result["pdf_path"] is None
    assert result["report"].pdf_path is None


def test_simultaneous_same_target_pdfs_are_distinct(tmp_path, monkeypatch):
    monkeypatch.setattr(report_agent, "REPORTS_DIR", str(tmp_path))
    with ThreadPoolExecutor(max_workers=2) as pool:
        paths = list(pool.map(lambda _: report_agent._generate_pdf(ReportData(), "same.example"), range(2)))
    assert paths[0] != paths[1]
    for path in paths:
        from pathlib import Path
        assert Path(path).read_bytes().startswith(b"%PDF")
        assert Path(path).parent == tmp_path
