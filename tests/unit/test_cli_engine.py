from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from typer.testing import CliRunner

from vibeshield.cli import app
from vibeshield.models.finding import Finding, SeverityLevel
from vibeshield.models.recon import ReconData
from vibeshield.models.report import (
    FingerprintResult,
    JSONReport,
    PlainReport,
    ScanMetadata,
    Summary,
)
from vibeshield.scanner.engine import ScannerEngine

runner = CliRunner()


class TestCLI:
    @pytest.fixture
    def mock_engine_class(self):
        with patch("vibeshield.cli.ScannerEngine") as mock_class:
            engine_instance = AsyncMock()
            mock_class.return_value = engine_instance
            
            plain_report = PlainReport(
                scan_metadata=ScanMetadata(
                    target="http://example.com",
                    timestamp="2024-01-01T00:00:00Z",
                    version="1.0.0",
                    duration_ms=1000,
                    crawl_depth=2,
                    max_pages=20,
                    pages_crawled=1,
                    checks_run=["ExposedSecretsCheck"]
                ),
                fingerprint=FingerprintResult(framework=None, framework_version=None, baas=[], technologies=[], headers={}, js_bundles=[], api_endpoints=[]),
                findings=[],
                summary=Summary(critical=0, high=0, medium=0, low=0, info=0)
            )
            json_report = JSONReport(
                scan_metadata=ScanMetadata(
                    target="http://example.com",
                    timestamp="2024-01-01T00:00:00Z",
                    version="1.0.0",
                    duration_ms=1000,
                    crawl_depth=2,
                    max_pages=20,
                    pages_crawled=1,
                    checks_run=["ExposedSecretsCheck"]
                ),
                fingerprint=FingerprintResult(framework=None, framework_version=None, baas=[], technologies=[], headers={}, js_bundles=[], api_endpoints=[]),
                findings=[],
                summary=Summary(critical=0, high=0, medium=0, low=0, info=0)
            )
            engine_instance.run.return_value = (plain_report, json_report)
            yield mock_class, engine_instance

    @pytest.fixture
    def mock_plain_reporter(self):
        with patch("vibeshield.cli.PlainReporter") as mock_class:
            mock_class.generate.return_value = "Plain report output"
            yield mock_class

    @pytest.fixture
    def mock_json_reporter(self):
        with patch("vibeshield.cli.JSONReporter") as mock_class:
            mock_class.generate.return_value = '{"findings": []}'
            yield mock_class

    def test_scan_requires_confirm_ownership(self, mock_engine_class, mock_plain_reporter, mock_json_reporter):
        result = runner.invoke(app, ["scan", "http://example.com"])
        
        assert result.exit_code == 1
        assert "Ownership Confirmation Required" in result.output

    def test_scan_with_confirm_ownership_runs_engine(self, mock_engine_class, mock_plain_reporter, mock_json_reporter):
        mock_class, engine_instance = mock_engine_class
        
        result = runner.invoke(app, ["scan", "http://example.com", "--confirm-ownership"])
        
        assert result.exit_code == 0
        mock_class.assert_called_once_with(
            target_url="http://example.com",
            max_depth=2,
            max_pages=20,
            timeout=10.0,
            allow_write_tests=False
        )
        engine_instance.run.assert_called_once()
        mock_plain_reporter.generate.assert_called_once()

    def test_scan_with_allow_write_tests_passes_to_engine(self, mock_engine_class, mock_plain_reporter, mock_json_reporter):
        mock_class, _ = mock_engine_class
    
        result = runner.invoke(app, ["scan", "http://example.com", "--confirm-ownership", "--allow-write-tests"])
    
        assert result.exit_code == 0
        call_kwargs = mock_class.call_args.kwargs
        assert call_kwargs["allow_write_tests"] is True

    def test_scan_validates_url_scheme(self, mock_engine_class, mock_plain_reporter, mock_json_reporter):
        result = runner.invoke(app, ["scan", "example.com", "--confirm-ownership"])
        
        assert result.exit_code == 1
        assert "URL must start with http:// or https://" in result.output

    def test_scan_validates_output_format(self, mock_engine_class, mock_plain_reporter, mock_json_reporter):
        result = runner.invoke(app, ["scan", "http://example.com", "--confirm-ownership", "--output", "invalid"])
        
        assert result.exit_code == 1
        assert "Invalid output format" in result.output

    def test_scan_output_plain_only(self, mock_engine_class, mock_plain_reporter, mock_json_reporter):
        result = runner.invoke(app, ["scan", "http://example.com", "--confirm-ownership", "--output", "plain"])
        
        assert result.exit_code == 0
        mock_plain_reporter.generate.assert_called_once()
        mock_json_reporter.generate.assert_not_called()

    def test_scan_output_json_only(self, mock_engine_class, mock_plain_reporter, mock_json_reporter):
        result = runner.invoke(app, ["scan", "http://example.com", "--confirm-ownership", "--output", "json"])
        
        assert result.exit_code == 0
        mock_plain_reporter.generate.assert_not_called()
        mock_json_reporter.generate.assert_called_once()

    def test_scan_output_both(self, mock_engine_class, mock_plain_reporter, mock_json_reporter):
        result = runner.invoke(app, ["scan", "http://example.com", "--confirm-ownership", "--output", "both"])
        
        assert result.exit_code == 0
        mock_plain_reporter.generate.assert_called_once()
        mock_json_reporter.generate.assert_called_once()

    def test_scan_writes_to_file(self, mock_engine_class, mock_plain_reporter, mock_json_reporter, tmp_path):
        output_file = tmp_path / "report.json"
        
        result = runner.invoke(app, ["scan", "http://example.com", "--confirm-ownership", "--output", "json", "--output-file", str(output_file)])
        
        assert result.exit_code == 0
        assert output_file.exists()
        content = output_file.read_text()
        assert '{"findings": []}' in content

    def test_scan_custom_max_pages_max_depth_timeout(self, mock_engine_class, mock_plain_reporter, mock_json_reporter):
        mock_class, _ = mock_engine_class
        
        result = runner.invoke(app, [
            "scan", "http://example.com", "--confirm-ownership",
            "--max-pages", "50", "--max-depth", "3", "--timeout", "30.0"
        ])
        
        assert result.exit_code == 0
        call_kwargs = mock_class.call_args.kwargs
        assert call_kwargs["max_pages"] == 50
        assert call_kwargs["max_depth"] == 3
        assert call_kwargs["timeout"] == 30.0

    def test_scan_exit_code_critical(self, mock_engine_class, mock_plain_reporter, mock_json_reporter):
        _, engine_instance = mock_engine_class
        
        plain_report = PlainReport(
            scan_metadata=ScanMetadata(
                target="http://example.com", timestamp="2024-01-01T00:00:00Z",
                version="1.0.0", duration_ms=1000, crawl_depth=2, max_pages=20,
                pages_crawled=1, checks_run=[]
            ),
            fingerprint=FingerprintResult(framework=None, framework_version=None, baas=[], technologies=[], headers={}, js_bundles=[], api_endpoints=[]),
            findings=[
                Finding(
                    id="test-1", check="test", title="Test", severity=SeverityLevel.CRITICAL,
                    score=20, impact=5, likelihood=4, confidence=0.9,
                    remediation="Fix it", references=[], evidence=None,
                    wstg_id="WSTG-TEST", attck_ids=["T1234"]
                )
            ],
            summary=Summary(critical=1, high=0, medium=0, low=0, info=0)
        )
        json_report = JSONReport(
            scan_metadata=ScanMetadata(
                target="http://example.com", timestamp="2024-01-01T00:00:00Z",
                version="1.0.0", duration_ms=1000, crawl_depth=2, max_pages=20,
                pages_crawled=1, checks_run=[]
            ),
            fingerprint=FingerprintResult(framework=None, framework_version=None, baas=[], technologies=[], headers={}, js_bundles=[], api_endpoints=[]),
            findings=[],
            summary=Summary(critical=1, high=0, medium=0, low=0, info=0)
        )
        engine_instance.run.return_value = (plain_report, json_report)
        
        result = runner.invoke(app, ["scan", "http://example.com", "--confirm-ownership"])
        
        assert result.exit_code == 2

    def test_scan_exit_code_high(self, mock_engine_class, mock_plain_reporter, mock_json_reporter):
        _, engine_instance = mock_engine_class
        
        plain_report = PlainReport(
            scan_metadata=ScanMetadata(
                target="http://example.com", timestamp="2024-01-01T00:00:00Z",
                version="1.0.0", duration_ms=1000, crawl_depth=2, max_pages=20,
                pages_crawled=1, checks_run=[]
            ),
            fingerprint=FingerprintResult(framework=None, framework_version=None, baas=[], technologies=[], headers={}, js_bundles=[], api_endpoints=[]),
            findings=[
                Finding(
                    id="test-1", check="test", title="Test", severity=SeverityLevel.HIGH,
                    score=16, impact=4, likelihood=4, confidence=0.9,
                    remediation="Fix it", references=[], evidence=None,
                    wstg_id="WSTG-TEST", attck_ids=["T1234"]
                )
            ],
            summary=Summary(critical=0, high=1, medium=0, low=0, info=0)
        )
        json_report = JSONReport(
            scan_metadata=ScanMetadata(
                target="http://example.com", timestamp="2024-01-01T00:00:00Z",
                version="1.0.0", duration_ms=1000, crawl_depth=2, max_pages=20,
                pages_crawled=1, checks_run=[]
            ),
            fingerprint=FingerprintResult(framework=None, framework_version=None, baas=[], technologies=[], headers={}, js_bundles=[], api_endpoints=[]),
            findings=[],
            summary=Summary(critical=0, high=1, medium=0, low=0, info=0)
        )
        engine_instance.run.return_value = (plain_report, json_report)
        
        result = runner.invoke(app, ["scan", "http://example.com", "--confirm-ownership"])
        
        assert result.exit_code == 3

    def test_scan_exit_code_clean(self, mock_engine_class, mock_plain_reporter, mock_json_reporter):
        result = runner.invoke(app, ["scan", "http://example.com", "--confirm-ownership"])
        
        assert result.exit_code == 0

    def test_scan_keyboard_interrupt(self, mock_engine_class):
        _, engine_instance = mock_engine_class
        engine_instance.run.side_effect = KeyboardInterrupt()
        
        result = runner.invoke(app, ["scan", "http://example.com", "--confirm-ownership"])
        
        assert result.exit_code == 130
        assert "interrupted" in result.output.lower()

    def test_scan_exception_handled(self, mock_engine_class):
        _, engine_instance = mock_engine_class
        engine_instance.run.side_effect = Exception("Scan failed")
        
        result = runner.invoke(app, ["scan", "http://example.com", "--confirm-ownership"])
        
        assert result.exit_code == 1
        assert "Scan failed" in result.output

    def test_scan_allow_write_tests_shows_warning(self, mock_engine_class, mock_plain_reporter, mock_json_reporter):
        result = runner.invoke(app, ["scan", "http://example.com", "--confirm-ownership", "--allow-write-tests"])
        
        assert result.exit_code == 0
        assert "Write Tests Enabled" in result.output


class TestScannerEngine:
    @pytest.fixture
    def mock_http_client(self):
        with patch("vibeshield.scanner.engine.HTTPClient") as mock_class:
            client_instance = AsyncMock()
            mock_class.return_value.__aenter__.return_value = client_instance
            yield mock_class, client_instance

    @pytest.fixture
    def mock_reconnaissance(self):
        with patch("vibeshield.scanner.engine.Reconnaissance") as mock_class:
            recon_instance = AsyncMock()
            mock_class.return_value = recon_instance
            
            recon_data = ReconData(
                target_url="http://example.com",
                base_url="http://example.com",
                pages=[],
                fingerprint=FingerprintResult(framework=None, framework_version=None, baas=[], technologies=[], headers={}, js_bundles=[], api_endpoints=[])
            )
            recon_instance.run.return_value = recon_data
            yield mock_class, recon_instance, recon_data

    def make_mock_check_class(self, findings=None):
        mock_check_class = MagicMock()
        mock_check_class.__name__ = "MockCheck"
        mock_check_instance = AsyncMock()
        mock_check_instance.run.return_value = findings or []
        mock_check_class.return_value = mock_check_instance
        return mock_check_class, mock_check_instance

    @pytest.mark.asyncio
    async def test_engine_runs_reconnaissance(self, mock_http_client, mock_reconnaissance):
        _, http_client = mock_http_client
        mock_recon_class, recon_instance, _ = mock_reconnaissance
        
        mock_check_class, _ = self.make_mock_check_class()
        
        with patch("vibeshield.scanner.engine.ALL_CHECKS", [mock_check_class]):
            engine = ScannerEngine(target_url="http://example.com")
            await engine.run()
        
        mock_recon_class.assert_called_once_with(
            target_url="http://example.com",
            max_depth=2,
            max_pages=20
        )
        recon_instance.run.assert_called_once_with(http_client)

    @pytest.mark.asyncio
    async def test_engine_runs_all_checks(self, mock_http_client, mock_reconnaissance):
        _, http_client = mock_http_client
        _, _, recon_data = mock_reconnaissance
        
        mock_check_class, mock_check_instance = self.make_mock_check_class()
        
        with patch("vibeshield.scanner.engine.ALL_CHECKS", [mock_check_class]):
            engine = ScannerEngine(target_url="http://example.com")
            await engine.run()
        
        mock_check_class.assert_called_once()
        mock_check_instance.run.assert_called_once_with(recon_data, http_client)

    @pytest.mark.asyncio
    async def test_engine_passes_allow_write_tests_to_checks(self, mock_http_client, mock_reconnaissance):
        _, _ = mock_http_client
        _, _, _ = mock_reconnaissance
        
        mock_check_class, mock_check_instance = self.make_mock_check_class()
        
        with patch("vibeshield.scanner.engine.ALL_CHECKS", [mock_check_class]):
            engine = ScannerEngine(target_url="http://example.com", allow_write_tests=True)
            await engine.run()
        
        assert mock_check_instance.allow_write_tests is True

    @pytest.mark.asyncio
    async def test_engine_sorts_findings_by_severity_and_score(self, mock_http_client, mock_reconnaissance):
        _, _ = mock_http_client
        _, _, _ = mock_reconnaissance
        
        finding_low = Finding(
            id="low", check="test", title="Low", severity=SeverityLevel.LOW,
            score=4, impact=2, likelihood=2, confidence=0.9,
            remediation="Fix", references=[], evidence=None,
            wstg_id="WSTG-TEST", attck_ids=["T1234"]
        )
        finding_high = Finding(
            id="high", check="test", title="High", severity=SeverityLevel.HIGH,
            score=16, impact=4, likelihood=4, confidence=0.9,
            remediation="Fix", references=[], evidence=None,
            wstg_id="WSTG-TEST", attck_ids=["T1234"]
        )
        finding_critical = Finding(
            id="critical", check="test", title="Critical", severity=SeverityLevel.CRITICAL,
            score=20, impact=5, likelihood=4, confidence=0.9,
            remediation="Fix", references=[], evidence=None,
            wstg_id="WSTG-TEST", attck_ids=["T1234"]
        )
        
        mock_check_class, _ = self.make_mock_check_class([finding_low, finding_high, finding_critical])
        
        with patch("vibeshield.scanner.engine.ALL_CHECKS", [mock_check_class]):
            engine = ScannerEngine(target_url="http://example.com")
            plain_report, _ = await engine.run()
        
        findings = plain_report.findings
        assert findings[0].severity == SeverityLevel.CRITICAL
        assert findings[1].severity == SeverityLevel.HIGH
        assert findings[2].severity == SeverityLevel.LOW

    @pytest.mark.asyncio
    async def test_engine_calculates_severity_for_findings_without_wstg(self, mock_http_client, mock_reconnaissance):
        _, _ = mock_http_client
        _, _, _ = mock_reconnaissance
        
        finding_no_wstg = Finding(
            id="test", check="test", title="Test", severity=SeverityLevel.INFO,
            score=0, impact=3, likelihood=3, confidence=0.9,
            remediation="Fix", references=[], evidence=None,
            wstg_id=None, attck_ids=[]
        )
        
        mock_check_class, _ = self.make_mock_check_class([finding_no_wstg])
        
        with patch("vibeshield.scanner.engine.ALL_CHECKS", [mock_check_class]):
            engine = ScannerEngine(target_url="http://example.com")
            plain_report, _ = await engine.run()
        
        assert plain_report.findings[0].severity != SeverityLevel.INFO
        assert plain_report.findings[0].score > 0

    @pytest.mark.asyncio
    async def test_engine_builds_scan_metadata(self, mock_http_client, mock_reconnaissance):
        _, _ = mock_http_client
        _, _, recon_data = mock_reconnaissance
        recon_data.pages = [MagicMock(), MagicMock()]
        
        mock_check_class, _ = self.make_mock_check_class()
        
        with patch("vibeshield.scanner.engine.ALL_CHECKS", [mock_check_class]):
            engine = ScannerEngine(
                target_url="http://example.com",
                max_depth=3,
                max_pages=50,
                timeout=15.0
            )
            plain_report, _ = await engine.run()
        
        metadata = plain_report.scan_metadata
        assert metadata.target == "http://example.com"
        assert metadata.crawl_depth == 3
        assert metadata.max_pages == 50
        assert metadata.pages_crawled == 2
        assert metadata.version == "1.0.0"
        assert "Z" in metadata.timestamp

    @pytest.mark.asyncio
    async def test_engine_builds_summary(self, mock_http_client, mock_reconnaissance):
        _, _ = mock_http_client
        _, _, _ = mock_reconnaissance
        
        findings = [
            Finding(id="1", check="c1", title="C1", severity=SeverityLevel.CRITICAL, score=20, impact=5, likelihood=4, confidence=0.9, remediation="", references=[], evidence=None, wstg_id="WSTG-TEST", attck_ids=["T1234"]),
            Finding(id="2", check="c2", title="C2", severity=SeverityLevel.HIGH, score=16, impact=4, likelihood=4, confidence=0.9, remediation="", references=[], evidence=None, wstg_id="WSTG-TEST", attck_ids=["T1234"]),
            Finding(id="3", check="c3", title="C3", severity=SeverityLevel.HIGH, score=12, impact=3, likelihood=4, confidence=0.9, remediation="", references=[], evidence=None, wstg_id="WSTG-TEST", attck_ids=["T1234"]),
            Finding(id="4", check="c4", title="C4", severity=SeverityLevel.MEDIUM, score=9, impact=3, likelihood=3, confidence=0.9, remediation="", references=[], evidence=None, wstg_id="WSTG-TEST", attck_ids=["T1234"]),
            Finding(id="5", check="c5", title="C5", severity=SeverityLevel.LOW, score=4, impact=2, likelihood=2, confidence=0.9, remediation="", references=[], evidence=None, wstg_id="WSTG-TEST", attck_ids=["T1234"]),
            Finding(id="6", check="c6", title="C6", severity=SeverityLevel.INFO, score=2, impact=1, likelihood=2, confidence=0.9, remediation="", references=[], evidence=None, wstg_id="WSTG-TEST", attck_ids=["T1234"]),
        ]
        
        mock_check_class, _ = self.make_mock_check_class(findings)
        
        with patch("vibeshield.scanner.engine.ALL_CHECKS", [mock_check_class]):
            engine = ScannerEngine(target_url="http://example.com")
            plain_report, _ = await engine.run()
        
        summary = plain_report.summary
        assert summary.critical == 1
        assert summary.high == 2
        assert summary.medium == 1
        assert summary.low == 1
        assert summary.info == 1

    @pytest.mark.asyncio
    async def test_engine_handles_check_exception_gracefully(self, mock_http_client, mock_reconnaissance):
        _, _ = mock_http_client
        _, _, _ = mock_reconnaissance
        
        mock_check_class1, _ = self.make_mock_check_class()
        mock_check_class1.return_value.run.side_effect = Exception("Check failed")
        
        mock_check_class2, _ = self.make_mock_check_class()
        
        with patch("vibeshield.scanner.engine.ALL_CHECKS", [mock_check_class1, mock_check_class2]):
            engine = ScannerEngine(target_url="http://example.com")
            plain_report, _ = await engine.run()
        
        assert len(plain_report.findings) == 0

    @pytest.mark.asyncio
    async def test_engine_uses_custom_parameters(self, mock_http_client, mock_reconnaissance):
        mock_http_class, _ = mock_http_client
        mock_recon_class, _, _ = mock_reconnaissance
        
        mock_check_class, _ = self.make_mock_check_class()
        
        with patch("vibeshield.scanner.engine.ALL_CHECKS", [mock_check_class]):
            engine = ScannerEngine(
                target_url="http://example.com",
                max_depth=5,
                max_pages=100,
                timeout=30.0,
                allow_write_tests=True
            )
            await engine.run()
        
        mock_recon_class.assert_called_once_with(
            target_url="http://example.com",
            max_depth=5,
            max_pages=100
        )
        mock_http_class.assert_called_once_with(timeout=30.0)