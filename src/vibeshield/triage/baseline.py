from vibeshield.models.finding import Finding, SeverityLevel
from vibeshield.scanner.scoring import calculate_severity
from vibeshield.triage.models import TriageResult

SEVERITY_RANK = {
    SeverityLevel.CRITICAL: 5,
    SeverityLevel.HIGH: 4,
    SeverityLevel.MEDIUM: 3,
    SeverityLevel.LOW: 2,
    SeverityLevel.INFO: 1,
}


def baseline_rank(findings: list[Finding]) -> list[TriageResult]:
    """Generate baseline triage results using severity scoring only.
    
    This is the non-AI comparison baseline: sorts by severity score,
    maps to TriageResult with minimal explanation.
    """
    # Ensure findings have severity/score calculated
    results: list[TriageResult] = []
    
    for finding in findings:
        # Use existing severity/score or recalculate
        if finding.score == 0:
            severity, _ = calculate_severity(finding.impact, finding.likelihood)
        else:
            severity = finding.severity
        
        # Map severity to priority (1-5)
        priority = SEVERITY_RANK.get(severity, 1)
        
        results.append(TriageResult(
            finding=finding,
            explanation=f"Scanner detected {finding.title.lower()}. Severity: {severity.value}. "
                        f"Review evidence and apply recommended remediation.",
            exploitability=priority,  # Baseline assumes exploitability ≈ severity
            fix=finding.remediation,
            revised_priority=priority,
            source="baseline",
            prompt_version="baseline",
        ))
    
    # Sort by revised_priority descending, then by score descending
    results.sort(key=lambda r: (-r.revised_priority, -r.finding.score))
    return results