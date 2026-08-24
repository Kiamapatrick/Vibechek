import json

import pytest

from vibeshield.models.finding import Evidence, Finding, SeverityLevel
from vibeshield.models.report import (
    FingerprintResult,
    JSONReport,
    PlainReport,
    ScanMetadata,
    Summary,
)
from vibeshield.reporting.json import JSONReporter
from vibeshield.reporting.plain import PlainReporter


@pytest.fixture
def sample_finding():
    return Finding(
        check="exposed_secrets",
        title="Exposed AWS Key",
        severity=SeverityLevel.CRITICAL,
        score=20,
        impact=5,
        likelihood=4,
        wstg_id="WSTG-INFO-02",
        attck_ids=["T1552.001"],
        evidence=Evidence(
            url="https://example.com/main.js",
            snippet="const key = 'AKIA...'",
            matched_pattern="AKIA...",
        ),
        confidence=0.9,
        remediation="Rotate key immediately. Move to server-side env var.",
        references=["https://owasp.org/..."],
    )


@pytest.fixture
def sample_reports(sample_finding):
    metadata = ScanMetadata(
        target="https://example.com",
        timestamp="2024-01-01T00:00:00Z",
        version="0.1.0",
        duration_ms=5000,
        crawl_depth=2,
        max_pages=20,
        pages_crawled=5,
        checks_run=["ExposedSecretsCheck"],
    )
    fingerprint = FingerprintResult(framework="nextjs", baas=["supabase"])
    summary = Summary(critical=1, high=0, medium=0, low=0, info=0)

    plain = PlainReport(
        scan_metadata=metadata,
        fingerprint=fingerprint,
        findings=[sample_finding],
        summary=summary,
    )

    json_report = JSONReport(
        scan_metadata=metadata,
        fingerprint=fingerprint,
        findings=[sample_finding],
        summary=summary,
    )

    return plain, json_report


class TestPlainReporter:
    def test_generates_text(self, sample_reports):
        plain_report, _ = sample_reports
        output = PlainReporter.generate(plain_report)
        assert "VibeShield Security Scan Report" in output
        assert "https://example.com" in output
        assert "Exposed AWS Key" in output
        assert "Critical" in output
        assert "Rotate key immediately" in output

    def test_empty_findings(self):
        metadata = ScanMetadata(
            target="https://example.com",
            timestamp="2024-01-01T00:00:00Z",
            version="0.1.0",
            duration_ms=1000,
            crawl_depth=2,
            max_pages=20,
            pages_crawled=1,
            checks_run=[],
        )
        report = PlainReport(
            scan_metadata=metadata,
            fingerprint=FingerprintResult(),
            findings=[],
            summary=Summary(),
        )
        output = PlainReporter.generate(report)
        assert "No issues found" in output


class TestJSONReporter:
    def test_generates_valid_json(self, sample_reports):
        _, json_report = sample_reports
        output = JSONReporter.generate(json_report)
        data = json.loads(output)
        assert data["scan_metadata"]["target"] == "https://example.com"
        assert len(data["findings"]) == 1
        assert data["findings"][0]["check"] == "exposed_secrets"
        assert data["summary"]["critical"] == 1

    def test_write_to_file(self, sample_reports, tmp_path):
        _, json_report = sample_reports
        filepath = tmp_path / "report.json"
        JSONReporter.write_to_file(json_report, str(filepath))
        assert filepath.exists()
        data = json.loads(filepath.read_text())
        assert data["scan_metadata"]["target"] == "https://example.com"