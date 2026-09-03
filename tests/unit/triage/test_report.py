import pytest

from vibeshield.models.finding import Evidence, Finding, SeverityLevel
from vibeshield.triage.models import TriageResult
from vibeshield.triage.report import generate_report


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


def _make_triage_result(finding: Finding, **overrides) -> TriageResult:
    defaults = {
        "finding": finding,
        "explanation": "Test explanation",
        "exploitability": 4,
        "fix": "Test fix",
        "revised_priority": 4,
        "source": "llm",
        "prompt_version": "v1",
    }
    defaults.update(overrides)
    return TriageResult(**defaults)


class TestGenerateReport:
    def test_basic_generation_with_findings(self):
        finding = _make_finding()
        result = _make_triage_result(finding)
        output = generate_report([result])

        assert "VibeShield Security Triage Report" in output
        assert "Total findings triaged: 1" in output
        assert "Priority 4 (HIGH): 1" in output
        assert "Exposed AWS Access Key" in output
        assert "Test explanation" in output
        assert "Test fix" in output
        assert "http://localhost:8080" in output
        assert "Rotate key" in output
        assert "End of triage report" in output

    def test_empty_results_list(self):
        output = generate_report([])
        assert "No findings to triage." in output

    def test_snippet_not_truncated_when_short(self):
        finding = _make_finding(
            evidence=Evidence(url="http://test.com", snippet="short snippet")
        )
        result = _make_triage_result(finding)
        output = generate_report([result])

        # Short snippet should NOT have "..."
        assert "Evidence: short snippet" in output
        assert "Evidence: short snippet..." not in output

    def test_snippet_truncated_with_ellipsis_when_long(self):
        long_snippet = "x" * 250
        finding = _make_finding(evidence=Evidence(url="http://test.com", snippet=long_snippet))
        result = _make_triage_result(finding)
        output = generate_report([result])

        # Long snippet SHOULD be truncated with "..."
        assert "Evidence: " + "x" * 200 + "..." in output
        assert "Evidence: " + long_snippet not in output

    def test_snippet_exactly_200_chars_no_ellipsis(self):
        exact_200 = "x" * 200
        finding = _make_finding(evidence=Evidence(url="http://test.com", snippet=exact_200))
        result = _make_triage_result(finding)
        output = generate_report([result])

        assert "Evidence: " + "x" * 200 in output
        assert "Evidence: " + "x" * 200 + "..." not in output

    def test_snippet_201_chars_has_ellipsis(self):
        exact_201 = "x" * 201
        finding = _make_finding(evidence=Evidence(url="http://test.com", snippet=exact_201))
        result = _make_triage_result(finding)
        output = generate_report([result])

        assert "Evidence: " + "x" * 200 + "..." in output

    def test_sorting_by_revised_priority_then_severity(self):
        f1 = _make_finding(id="f1", title="Low priority, Critical severity", severity=SeverityLevel.CRITICAL)
        f2 = _make_finding(id="f2", title="High priority, Low severity", severity=SeverityLevel.LOW)

        r1 = _make_triage_result(f1, revised_priority=2)
        r2 = _make_triage_result(f2, revised_priority=4)

        output = generate_report([r1, r2])

        # f2 (priority 4) should come before f1 (priority 2)
        f2_pos = output.index("High priority, Low severity")
        f1_pos = output.index("Low priority, Critical severity")
        assert f2_pos < f1_pos

    def test_same_priority_sorts_by_original_severity(self):
        f1 = _make_finding(id="f1", title="Critical severity", severity=SeverityLevel.CRITICAL, score=20)
        f2 = _make_finding(id="f2", title="High severity", severity=SeverityLevel.HIGH, score=16)

        r1 = _make_triage_result(f1, revised_priority=3)
        r2 = _make_triage_result(f2, revised_priority=3)

        output = generate_report([r1, r2])

        # Critical should come before High when same priority
        critical_pos = output.index("Critical severity")
        high_pos = output.index("High severity")
        assert critical_pos < high_pos

    def test_source_breakdown_llm_and_baseline(self):
        f1 = _make_finding(id="f1")
        f2 = _make_finding(id="f2")

        r1 = _make_triage_result(f1, source="llm")
        r2 = _make_triage_result(f2, source="baseline")

        output = generate_report([r1, r2])

        assert "Sources: 1 LLM, 1 baseline" in output

    def test_source_breakdown_only_llm(self):
        finding = _make_finding()
        result = _make_triage_result(finding, source="llm")
        output = generate_report([result])

        assert "Sources:" not in output  # Only shown when both sources present

    def test_source_breakdown_only_baseline(self):
        finding = _make_finding()
        result = _make_triage_result(finding, source="baseline")
        output = generate_report([result])

        assert "Sources:" not in output

    def test_priority_distribution_labels(self):
        findings = [
            _make_triage_result(_make_finding(id="f1"), revised_priority=5),
            _make_triage_result(_make_finding(id="f2"), revised_priority=4),
            _make_triage_result(_make_finding(id="f3"), revised_priority=3),
            _make_triage_result(_make_finding(id="f4"), revised_priority=2),
            _make_triage_result(_make_finding(id="f5"), revised_priority=1),
        ]
        output = generate_report(findings)

        assert "Priority 5 (CRITICAL): 1" in output
        assert "Priority 4 (HIGH): 1" in output
        assert "Priority 3 (MEDIUM): 1" in output
        assert "Priority 2 (LOW): 1" in output
        assert "Priority 1 (INFO): 1" in output

    def test_includes_all_fields_in_output(self):
        finding = _make_finding(
            check="cors",
            title="CORS Misconfiguration",
            evidence=Evidence(url="https://api.example.com", snippet="Access-Control-Allow-Origin: *"),
        )
        result = _make_triage_result(
            finding,
            explanation="CORS allows any origin",
            exploitability=3,
            fix="Restrict origins",
            revised_priority=3,
            source="llm",
            prompt_version="v2",
        )
        output = generate_report([result])

        assert "Check: cors" in output
        assert "Original Severity: CRITICAL" in output
        assert "Revised Priority: 3/5" in output
        assert "Exploitability: 3/5" in output
        assert "Source: llm (prompt: v2)" in output
        assert "CORS allows any origin" in output
        assert "Restrict origins" in output
        assert "https://api.example.com" in output
        assert "Access-Control-Allow-Origin" in output

    def test_remediation_included_when_present(self):
        finding = _make_finding(remediation="Custom remediation advice")
        result = _make_triage_result(finding)
        output = generate_report([result])

        assert "Scanner remediation: Custom remediation advice" in output

    def test_remediation_omitted_when_empty(self):
        finding = _make_finding(remediation="")
        result = _make_triage_result(finding)
        output = generate_report([result])

        assert "Scanner remediation:" not in output