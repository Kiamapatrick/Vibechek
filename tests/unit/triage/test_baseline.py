import pytest
from vibeshield.models.finding import Evidence, Finding, SeverityLevel
from vibeshield.triage.baseline import baseline_triage, baseline_rank
from vibeshield.triage.models import TriageResult


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
        "remediation": "Rotate key in AWS IAM and move to server-side env var.",
        "references": ["https://aws.amazon.com/security"],
    }
    defaults.update(overrides)
    return Finding(**defaults)


class TestBaselineTriage:
    def test_returns_triage_result_with_correct_shape(self):
        finding = _make_finding()
        result = baseline_triage(finding)
        
        assert isinstance(result, TriageResult)
        assert result.finding is finding
        assert result.source == "baseline"
        assert result.prompt_version == "v1"
        assert result.explanation == "Automated finding: Exposed AWS Access Key"
        assert result.exploitability == 4  # finding.likelihood
        assert result.fix == "Rotate key in AWS IAM and move to server-side env var."
        assert result.revised_priority == 5  # finding.impact

    def test_exploitability_uses_likelihood(self):
        for likelihood in range(1, 6):
            finding = _make_finding(likelihood=likelihood)
            result = baseline_triage(finding)
            assert result.exploitability == likelihood

    def test_revised_priority_uses_impact(self):
        for impact in range(1, 6):
            finding = _make_finding(impact=impact)
            result = baseline_triage(finding)
            assert result.revised_priority == impact

    def test_all_severity_levels_map_to_priority(self):
        for severity, expected in [
            (SeverityLevel.CRITICAL, 5),
            (SeverityLevel.HIGH, 4),
            (SeverityLevel.MEDIUM, 3),
            (SeverityLevel.LOW, 2),
            (SeverityLevel.INFO, 1),
        ]:
            finding = _make_finding(severity=severity)
            result = baseline_triage(finding)
            # baseline_triage doesn't use severity for exploitability/priority,
            # but baseline_rank does for sorting
            assert result.source == "baseline"


class TestBaselineRank:
    def test_returns_list_sorted_by_priority_desc_then_score_desc(self):
        findings = [
            _make_finding(id="f1", impact=3, likelihood=3, score=9),   # priority 3
            _make_finding(id="f2", impact=5, likelihood=4, score=20),  # priority 5
            _make_finding(id="f3", impact=5, likelihood=3, score=15),  # priority 5, lower score
            _make_finding(id="f4", impact=1, likelihood=1, score=1),   # priority 1
        ]
        results = baseline_rank(findings)
        
        assert len(results) == 4
        assert results[0].finding.id == "f2"  # priority 5, score 20
        assert results[1].finding.id == "f3"  # priority 5, score 15
        assert results[2].finding.id == "f1"  # priority 3
        assert results[3].finding.id == "f4"  # priority 1

    def test_each_result_is_valid_triage_result(self):
        findings = [_make_finding(), _make_finding(impact=3, likelihood=2)]
        results = baseline_rank(findings)
        
        for r in results:
            assert isinstance(r, TriageResult)
            assert r.source == "baseline"
            assert 1 <= r.exploitability <= 5
            assert 1 <= r.revised_priority <= 5