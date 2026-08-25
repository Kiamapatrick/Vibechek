import pytest

from vibeshield.models.finding import Evidence, Finding, SeverityLevel
from vibeshield.triage.models import ContextSnippet, TriageResult


class TestContextSnippet:
    def test_creation(self):
        snippet = ContextSnippet(
            topic="exposed_secrets",
            content="Test content about exposed secrets",
            source_file="exposed_secrets.md",
        )
        assert snippet.topic == "exposed_secrets"
        assert snippet.content == "Test content about exposed secrets"
        assert snippet.source_file == "exposed_secrets.md"

    def test_empty_content_allowed(self):
        snippet = ContextSnippet(topic="test", content="", source_file="test.md")
        assert snippet.content == ""


class TestTriageResult:
    def _sample_finding(self) -> Finding:
        return Finding(
            check="exposed_secrets",
            title="Exposed AWS Key",
            severity=SeverityLevel.CRITICAL,
            score=20,
            impact=5,
            likelihood=4,
            wstg_id="WSTG-AUTH-07",
            attck_ids=["T1552"],
            evidence=Evidence(
                url="https://example.com/main.js",
                snippet="const AWS_KEY = 'AKIA...'",
                matched_pattern="AKIA...",
                response_status=200,
            ),
            confidence=0.9,
            remediation="Rotate key",
            references=["https://aws.amazon.com/security"],
        )

    def test_valid_creation_llm(self):
        finding = self._sample_finding()
        result = TriageResult(
            finding=finding,
            explanation="An AWS access key was found in client-side JavaScript.",
            exploitability=5,
            fix="Rotate the key in AWS IAM and move to server-side env var.",
            revised_priority=5,
            source="llm",
            prompt_version="v1",
        )
        assert result.finding is finding
        assert result.explanation == "An AWS access key was found in client-side JavaScript."
        assert result.exploitability == 5
        assert result.fix == "Rotate the key in AWS IAM and move to server-side env var."
        assert result.revised_priority == 5
        assert result.source == "llm"
        assert result.prompt_version == "v1"

    def test_valid_creation_baseline(self):
        finding = self._sample_finding()
        result = TriageResult(
            finding=finding,
            explanation="Scanner detected exposed AWS key.",
            exploitability=5,
            fix="Rotate key",
            revised_priority=5,
            source="baseline",
            prompt_version="baseline",
        )
        assert result.source == "baseline"
        assert result.prompt_version == "baseline"

    def test_exploitability_too_low_raises(self):
        finding = self._sample_finding()
        with pytest.raises(ValueError, match="exploitability must be between 1 and 5"):
            TriageResult(
                finding=finding,
                explanation="Test",
                exploitability=0,
                fix="Test",
                revised_priority=3,
            )

    def test_exploitability_too_high_raises(self):
        finding = self._sample_finding()
        with pytest.raises(ValueError, match="exploitability must be between 1 and 5"):
            TriageResult(
                finding=finding,
                explanation="Test",
                exploitability=6,
                fix="Test",
                revised_priority=3,
            )

    def test_revised_priority_too_low_raises(self):
        finding = self._sample_finding()
        with pytest.raises(ValueError, match="revised_priority must be between 1 and 5"):
            TriageResult(
                finding=finding,
                explanation="Test",
                exploitability=3,
                fix="Test",
                revised_priority=0,
            )

    def test_revised_priority_too_high_raises(self):
        finding = self._sample_finding()
        with pytest.raises(ValueError, match="revised_priority must be between 1 and 5"):
            TriageResult(
                finding=finding,
                explanation="Test",
                exploitability=3,
                fix="Test",
                revised_priority=6,
            )

    def test_invalid_source_raises(self):
        finding = self._sample_finding()
        with pytest.raises(ValueError, match="source must be 'llm' or 'baseline'"):
            TriageResult(
                finding=finding,
                explanation="Test",
                exploitability=3,
                fix="Test",
                revised_priority=3,
                source="invalid",
            )

    def test_defaults(self):
        finding = self._sample_finding()
        result = TriageResult(
            finding=finding,
            explanation="Test",
            exploitability=3,
            fix="Test",
            revised_priority=3,
        )
        assert result.source == "llm"
        assert result.prompt_version == "v1"

    def test_exploitability_boundaries(self):
        finding = self._sample_finding()
        for val in [1, 2, 3, 4, 5]:
            result = TriageResult(
                finding=finding,
                explanation="Test",
                exploitability=val,
                fix="Test",
                revised_priority=val,
            )
            assert result.exploitability == val
            assert result.revised_priority == val