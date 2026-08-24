from vibeshield.models.finding import Evidence, Finding, SeverityLevel
from vibeshield.models.report import FingerprintResult, JSONReport, ScanMetadata, Summary


class TestJSONReportSerialization:
    def test_finding_to_dict(self):
        finding = Finding(
            check="test",
            title="Test Finding",
            severity=SeverityLevel.HIGH,
            score=16,
            impact=4,
            likelihood=4,
            wstg_id="WSTG-TEST-01",
            attck_ids=["T1234"],
            evidence=Evidence(
                url="https://example.com",
                snippet="test",
            ),
            confidence=0.8,
            remediation="Fix it",
            references=["https://example.com"],
        )
        d = finding.to_dict()
        assert d["check"] == "test"
        assert d["severity"] == "High"
        assert d["score"] == 16
        assert d["wstg_id"] == "WSTG-TEST-01"
        assert d["attck_ids"] == ["T1234"]

    def test_finding_from_dict(self):
        data = {
            "id": "finding-abc123",
            "check": "test",
            "title": "Test",
            "severity": "Medium",
            "score": 9,
            "impact": 3,
            "likelihood": 3,
            "wstg_id": "WSTG-TEST-01",
            "attck_ids": ["T1234"],
            "evidence": {
                "url": "https://example.com",
                "snippet": "test",
                "matched_pattern": None,
                "request_headers": {},
                "response_headers": {},
                "response_status": 200,
            },
            "confidence": 0.8,
            "remediation": "Fix it",
            "references": ["https://example.com"],
        }
        finding = Finding.from_dict(data)
        assert finding.id == "finding-abc123"
        assert finding.severity == SeverityLevel.MEDIUM

    def test_json_report_to_dict(self):
        metadata = ScanMetadata(
            target="https://example.com",
            timestamp="2024-01-01T00:00:00Z",
            version="0.1.0",
            duration_ms=1000,
            crawl_depth=2,
            max_pages=20,
            pages_crawled=5,
            checks_run=["TestCheck"],
        )
        report = JSONReport(
            scan_metadata=metadata,
            fingerprint=FingerprintResult(),
            findings=[],
            summary=Summary(),
        )
        d = report.to_dict()
        assert d["scan_metadata"]["target"] == "https://example.com"
        assert d["fingerprint"]["framework"] is None
        assert d["findings"] == []