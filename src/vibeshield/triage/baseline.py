from vibeshield.models.finding import Finding, SeverityLevel
from vibeshield.triage.models import TriageResult

SEVERITY_RANK = {
    SeverityLevel.CRITICAL: 5,
    SeverityLevel.HIGH: 4,
    SeverityLevel.MEDIUM: 3,
    SeverityLevel.LOW: 2,
    SeverityLevel.INFO: 1,
}


def baseline_triage(finding: Finding) -> TriageResult:
    """Non-AI triage for a single finding: reuses scanner's own severity/impact/likelihood.
    
    No explanation/fix generation — this is the control-group comparison for eval.
    """
    return TriageResult(
        finding=finding,
        explanation=f"Automated finding: {finding.title}",
        exploitability=finding.likelihood,   # reuse Phase 1's own 1-5 scale
        fix=finding.remediation,             # Phase 1 checks already produce this
        revised_priority=finding.impact,     # reuse Phase 1's own 1-5 scale
        source="baseline",
        prompt_version="v1",
    )


def baseline_rank(findings: list[Finding]) -> list[TriageResult]:
    """Generate baseline triage results using severity scoring only.
    
    Kept for batch use (e.g., eval harness comparison).
    """
    results = [baseline_triage(f) for f in findings]
    results.sort(key=lambda r: (-r.revised_priority, -r.finding.score))
    return results