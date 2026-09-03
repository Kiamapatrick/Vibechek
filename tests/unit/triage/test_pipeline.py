import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from vibeshield.models.finding import Evidence, Finding, SeverityLevel
from vibeshield.triage.models import TriageResult
from vibeshield.triage.pipeline import run_full_pipeline


def _make_finding(**overrides) -> Finding:
    defaults = {
        "check": "exposed_secrets",
        "title": "Exposed AWS Access Key",
        "severity": SeverityLevel.CRITICAL,
        "score": 20,
        "impact": 5,
        "likelihood": 4,
        "wstg_id": "WSTG-INFO-02",
        "attck_ids": ["T1552.001"],
        "evidence": Evidence(url="http://localhost:8080", snippet='const apiKey = "AKIA..."'),
        "confidence": 0.9,
        "remediation": "Rotate key",
        "references": [],
    }
    defaults.update(overrides)
    return Finding(**defaults)


def _sample_report_dict(findings: list[dict]) -> dict:
    return {
        "scan_metadata": {
            "target": "https://example.com",
            "timestamp": "2024-01-01T00:00:00Z",
            "version": "1.0.0",
            "duration_ms": 5000,
            "crawl_depth": 2,
            "max_pages": 20,
            "pages_crawled": 5,
            "checks_run": ["ExposedSecretsCheck"],
        },
        "fingerprint": {
            "framework": "Next.js",
            "framework_version": "14.0.0",
            "baas": [],
            "technologies": ["Next.js"],
            "headers": {},
            "js_bundles": [],
            "api_endpoints": [],
        },
        "findings": findings,
        "summary": {
            "critical": sum(1 for f in findings if f.get("severity") == "Critical"),
            "high": sum(1 for f in findings if f.get("severity") == "High"),
            "medium": sum(1 for f in findings if f.get("severity") == "Medium"),
            "low": sum(1 for f in findings if f.get("severity") == "Low"),
            "info": sum(1 for f in findings if f.get("severity") == "Info"),
        },
    }


class TestRunFullPipeline:
    def test_end_to_end_with_mocked_triage(self):
        findings_data = [
            _make_finding(id="f1").to_dict(),
            _make_finding(id="f2", title="CORS misconfig", severity=SeverityLevel.HIGH).to_dict(),
        ]
        report_data = _sample_report_dict(findings_data)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(report_data, f)
            temp_path = Path(f.name)

        try:
            with (
                patch("vibeshield.triage.pipeline.run_triage") as mock_run_triage,
            ):
                mock_run_triage.return_value = [
                    TriageResult(
                        finding=_make_finding(id="f1"),
                        explanation="LLM explanation 1",
                        exploitability=5,
                        fix="LLM fix 1",
                        revised_priority=5,
                        source="llm",
                        prompt_version="v1",
                    ),
                    TriageResult(
                        finding=_make_finding(id="f2", title="CORS misconfig", severity=SeverityLevel.HIGH),
                        explanation="LLM explanation 2",
                        exploitability=3,
                        fix="LLM fix 2",
                        revised_priority=3,
                        source="llm",
                        prompt_version="v1",
                    ),
                ]

                output = run_full_pipeline(temp_path)

            assert "VibeShield Security Triage Report" in output
            assert "Total findings triaged: 2" in output
            assert "Priority 5 (CRITICAL): 1" in output
            assert "Priority 3 (MEDIUM): 1" in output
            # Sources line only appears when BOTH LLM and baseline are present
            assert "Sources:" not in output
            assert "Exposed AWS Access Key" in output
            assert "CORS misconfig" in output
            assert "LLM explanation 1" in output
            assert "LLM explanation 2" in output

            mock_run_triage.assert_called_once()
            called_findings = mock_run_triage.call_args[0][0]
            assert len(called_findings) == 2
            assert called_findings[0].id == "f1"
            assert called_findings[1].id == "f2"
        finally:
            temp_path.unlink()

    def test_empty_findings_produces_valid_report(self):
        report_data = _sample_report_dict([])

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(report_data, f)
            temp_path = Path(f.name)

        try:
            output = run_full_pipeline(temp_path)

            assert "No findings to triage." in output
        finally:
            temp_path.unlink()

    def test_baseline_fallback_in_pipeline(self):
        finding_data = _make_finding(id="f1").to_dict()
        report_data = _sample_report_dict([finding_data])

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(report_data, f)
            temp_path = Path(f.name)

        try:
            with patch("vibeshield.triage.pipeline.run_triage") as mock_run_triage:
                mock_run_triage.return_value = [
                    TriageResult(
                        finding=_make_finding(id="f1"),
                        explanation="Automated finding: Exposed AWS Access Key",
                        exploitability=4,
                        fix="Rotate key",
                        revised_priority=5,
                        source="baseline",
                        prompt_version="v1",
                    ),
                ]

                output = run_full_pipeline(temp_path)

            assert "Sources:" not in output  # Only shown when both sources present
            assert "baseline" in output
        finally:
            temp_path.unlink()

    def test_nonexistent_file_raises(self):
        with pytest.raises(FileNotFoundError):
            run_full_pipeline(Path("/nonexistent/report.json"))

    def test_invalid_json_raises(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("{ not valid json }")
            temp_path = Path(f.name)

        try:
            with pytest.raises(json.JSONDecodeError):
                run_full_pipeline(temp_path)
        finally:
            temp_path.unlink()

    def test_missing_findings_key_works(self):
        report_data = {
            "scan_metadata": {"target": "https://example.com"},
            "fingerprint": {},
            "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(report_data, f)
            temp_path = Path(f.name)

        try:
            output = run_full_pipeline(temp_path)
            assert "No findings to triage." in output
        finally:
            temp_path.unlink()

    def test_preserves_all_finding_fields(self):
        finding_data = _make_finding(
            id="f1",
            wstg_id="WSTG-TEST-01",
            attck_ids=["T1234"],
            remediation="Custom fix",
        ).to_dict()
        report_data = _sample_report_dict([finding_data])

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(report_data, f)
            temp_path = Path(f.name)

        try:
            with patch("vibeshield.triage.pipeline.run_triage") as mock_run_triage:
                mock_run_triage.return_value = [
                    TriageResult(
                        finding=_make_finding(
                            id="f1",
                            wstg_id="WSTG-TEST-01",
                            attck_ids=["T1234"],
                            remediation="Custom fix",
                        ),
                        explanation="test",
                        exploitability=3,
                        fix="test fix",
                        revised_priority=3,
                        source="llm",
                        prompt_version="v1",
                    ),
                ]

                output = run_full_pipeline(temp_path)

            assert "Custom fix" in output
            assert "WSTG-TEST-01" not in output  # not in triage report output
        finally:
            temp_path.unlink()