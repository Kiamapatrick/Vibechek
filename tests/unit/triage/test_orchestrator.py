from unittest.mock import MagicMock, patch

from vibeshield.models.finding import Evidence, Finding, SeverityLevel
from vibeshield.triage.models import TriageResult
from vibeshield.triage.orchestrator import run_triage


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


class TestRunTriage:
    def test_happy_path_all_findings_triaged(self):
        findings = [_make_finding(id="f1"), _make_finding(id="f2", title="CORS misconfig")]

        with (
            patch("vibeshield.triage.orchestrator.get_retriever") as mock_get_retriever,
            patch("vibeshield.triage.orchestrator.get_client") as mock_get_client,
        ):
            mock_retriever = MagicMock()
            mock_retriever.retrieve.return_value = []
            mock_get_retriever.return_value = mock_retriever

            mock_client = MagicMock()
            mock_client.generate.side_effect = [
                TriageResult(
                    finding=findings[0], explanation="e1", exploitability=5,
                    fix="fix1", revised_priority=5, source="llm", prompt_version="v1"
                ),
                TriageResult(
                    finding=findings[1], explanation="e2", exploitability=3,
                    fix="fix2", revised_priority=3, source="llm", prompt_version="v1"
                ),
            ]
            mock_get_client.return_value = mock_client

            results = run_triage(findings)

        assert len(results) == 2
        assert results[0].source == "llm"
        assert results[1].source == "llm"
        assert mock_retriever.retrieve.call_count == 2
        assert mock_client.generate.call_count == 2

    def test_llm_failure_falls_back_to_baseline(self, caplog):
        finding = _make_finding()

        with (
            patch("vibeshield.triage.orchestrator.get_retriever") as mock_get_retriever,
            patch("vibeshield.triage.orchestrator.get_client") as mock_get_client,
        ):
            mock_retriever = MagicMock()
            mock_retriever.retrieve.return_value = []
            mock_get_retriever.return_value = mock_retriever

            mock_client = MagicMock()
            mock_client.generate.side_effect = Exception("Groq API error")
            mock_get_client.return_value = mock_client

            results = run_triage([finding])

        assert len(results) == 1
        assert results[0].source == "baseline"
        assert results[0].finding is finding

        # Verify warning was logged with exc_info
        assert "LLM triage failed for finding" in caplog.text
        assert "falling back to baseline" in caplog.text
        assert "Groq API error" in caplog.text

    def test_retriever_failure_falls_back_to_baseline(self, caplog):
        finding = _make_finding()

        with (
            patch("vibeshield.triage.orchestrator.get_retriever") as mock_get_retriever,
            patch("vibeshield.triage.orchestrator.get_client") as mock_get_client,
        ):
            mock_retriever = MagicMock()
            mock_retriever.retrieve.side_effect = Exception("BM25 index missing")
            mock_get_retriever.return_value = mock_retriever

            results = run_triage([finding])

        assert len(results) == 1
        assert results[0].source == "baseline"
        assert "LLM triage failed for finding" in caplog.text
        # Retriever failed before the LLM was ever called — confirms the
        # orchestrator doesn't attempt generation with incomplete context.
        mock_get_client.return_value.generate.assert_not_called()

    def test_mixed_success_and_failure(self, caplog):
        findings = [_make_finding(id="f1"), _make_finding(id="f2")]

        with (
            patch("vibeshield.triage.orchestrator.get_retriever") as mock_get_retriever,
            patch("vibeshield.triage.orchestrator.get_client") as mock_get_client,
        ):
            mock_retriever = MagicMock()
            mock_retriever.retrieve.return_value = []
            mock_get_retriever.return_value = mock_retriever

            mock_client = MagicMock()
            # First succeeds, second fails
            mock_client.generate.side_effect = [
                TriageResult(
                    finding=findings[0], explanation="ok", exploitability=4,
                    fix="fix", revised_priority=4, source="llm", prompt_version="v1"
                ),
                Exception("rate limit"),
            ]
            mock_get_client.return_value = mock_client

            results = run_triage(findings)

        assert len(results) == 2
        assert results[0].source == "llm"
        assert results[1].source == "baseline"
        assert "LLM triage failed for finding f2" in caplog.text

    def test_empty_findings_returns_empty_list(self):
        results = run_triage([])
        assert results == []

    def test_logging_uses_warning_level(self, caplog):
        finding = _make_finding()

        with (
            patch("vibeshield.triage.orchestrator.get_retriever") as mock_get_retriever,
            patch("vibeshield.triage.orchestrator.get_client") as mock_get_client,
        ):
            mock_retriever = MagicMock()
            mock_retriever.retrieve.return_value = []
            mock_get_retriever.return_value = mock_retriever

            mock_client = MagicMock()
            mock_client.generate.side_effect = Exception("test error")
            mock_get_client.return_value = mock_client

            with caplog.at_level("WARNING"):
                run_triage([finding])

        # Verify WARNING level (not INFO or ERROR)
        warning_records = [r for r in caplog.records if r.levelno == 30]
        assert len(warning_records) == 1
        assert "exc_info" in warning_records[0].__dict__