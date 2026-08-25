import json
import tempfile
from pathlib import Path

import pytest

from vibeshield.models.finding import SeverityLevel
from vibeshield.triage.ingest import load_report


class TestLoadReport:
    def _sample_report_dict(self, findings_count: int = 2) -> dict:
        findings = []
        for i in range(findings_count):
            findings.append({
                "id": f"finding-{i}",
                "check": "exposed_secrets",
                "title": f"Exposed Secret #{i}",
                "severity": "High",
                "score": 16,
                "impact": 4,
                "likelihood": 4,
                "wstg_id": "WSTG-AUTH-07",
                "attck_ids": ["T1552"],
                "evidence": {
                    "url": f"https://example.com/script{i}.js",
                    "snippet": f"const KEY = 'SECRET{i}'",
                    "matched_pattern": f"SECRET{i}",
                    "request_headers": {},
                    "response_headers": {"content-type": "application/javascript"},
                    "response_status": 200,
                },
                "confidence": 0.9,
                "remediation": "Rotate key",
                "references": ["https://example.com"],
            })
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
                "critical": 0,
                "high": findings_count,
                "medium": 0,
                "low": 0,
                "info": 0,
            },
        }

    def test_load_report_success(self):
        report_data = self._sample_report_dict(3)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(report_data, f)
            temp_path = Path(f.name)
        try:
            findings = load_report(temp_path)
            assert len(findings) == 3
            for i, finding in enumerate(findings):
                assert finding.id == f"finding-{i}"
                assert finding.check == "exposed_secrets"
                assert finding.title == f"Exposed Secret #{i}"
                assert finding.severity == SeverityLevel.HIGH
                assert finding.score == 16
                assert finding.evidence.snippet == f"const KEY = 'SECRET{i}'"
                assert finding.evidence.matched_pattern == f"SECRET{i}"
        finally:
            temp_path.unlink()

    def test_load_report_empty_findings(self):
        report_data = self._sample_report_dict(0)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(report_data, f)
            temp_path = Path(f.name)
        try:
            findings = load_report(temp_path)
            assert findings == []
        finally:
            temp_path.unlink()

    def test_load_report_missing_findings_key(self):
        report_data = {
            "scan_metadata": {"target": "https://example.com"},
            "fingerprint": {},
            "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(report_data, f)
            temp_path = Path(f.name)
        try:
            findings = load_report(temp_path)
            assert findings == []
        finally:
            temp_path.unlink()

    def test_load_report_invalid_json_raises(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("{ not valid json }")
            temp_path = Path(f.name)
        try:
            with pytest.raises(json.JSONDecodeError):
                load_report(temp_path)
        finally:
            temp_path.unlink()

    def test_load_report_nonexistent_file_raises(self):
        with pytest.raises(FileNotFoundError):
            load_report(Path("/nonexistent/report.json"))

    def test_load_report_preserves_all_fields(self):
        report_data = self._sample_report_dict(1)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(report_data, f)
            temp_path = Path(f.name)
        try:
            findings = load_report(temp_path)
            finding = findings[0]
            assert finding.wstg_id == "WSTG-AUTH-07"
            assert finding.attck_ids == ["T1552"]
            assert finding.confidence == 0.9
            assert finding.remediation == "Rotate key"
            assert finding.references == ["https://example.com"]
            assert finding.evidence.request_headers == {}
            assert finding.evidence.response_headers == {"content-type": "application/javascript"}
            assert finding.evidence.response_status == 200
        finally:
            temp_path.unlink()

    def test_load_report_handles_unicode(self):
        report_data = self._sample_report_dict(1)
        report_data["findings"][0]["evidence"]["snippet"] = "clé secrète: clé123 🔑"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump(report_data, f, ensure_ascii=False)
            temp_path = Path(f.name)
        try:
            findings = load_report(temp_path)
            assert "clé secrète" in findings[0].evidence.snippet
            assert "🔑" in findings[0].evidence.snippet
        finally:
            temp_path.unlink()

    def test_load_report_handles_missing_optional_evidence_fields(self):
        report_data = {
            "scan_metadata": {"target": "https://example.com"},
            "fingerprint": {},
            "findings": [{
                "id": "finding-test",
                "check": "test",
                "title": "Test",
                "severity": "Medium",
                "score": 9,
                "impact": 3,
                "likelihood": 3,
                "wstg_id": "",
                "attck_ids": [],
                "evidence": {
                    "url": "https://example.com",
                    "snippet": "test",
                },
                "confidence": 0.5,
                "remediation": "Fix",
                "references": [],
            }],
            "summary": {"critical": 0, "high": 0, "medium": 1, "low": 0, "info": 0},
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(report_data, f)
            temp_path = Path(f.name)
        try:
            findings = load_report(temp_path)
            assert len(findings) == 1
            finding = findings[0]
            assert finding.evidence.matched_pattern is None
            assert finding.evidence.request_headers == {}
            assert finding.evidence.response_headers == {}
            assert finding.evidence.response_status is None
        finally:
            temp_path.unlink()