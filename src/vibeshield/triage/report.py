from vibeshield.models.finding import SeverityLevel
from vibeshield.triage.models import TriageResult

SEVERITY_ORDER = [
    SeverityLevel.CRITICAL,
    SeverityLevel.HIGH,
    SeverityLevel.MEDIUM,
    SeverityLevel.LOW,
    SeverityLevel.INFO,
]

SEVERITY_LABEL = {
    SeverityLevel.CRITICAL: "CRITICAL",
    SeverityLevel.HIGH: "HIGH",
    SeverityLevel.MEDIUM: "MEDIUM",
    SeverityLevel.LOW: "LOW",
    SeverityLevel.INFO: "INFO",
}


def generate_report(results: list[TriageResult]) -> str:
    """Generate a plain-text triage report from TriageResult objects."""
    lines = []
    lines.append("=" * 70)
    lines.append("VibeShield Security Triage Report")
    lines.append("=" * 70)
    lines.append("")
    
    if not results:
        lines.append("No findings to triage.")
        return "\n".join(lines)
    
    # Summary
    total = len(results)
    by_priority: dict[int, int] = {}
    for r in results:
        by_priority[r.revised_priority] = by_priority.get(r.revised_priority, 0) + 1
    
    lines.append(f"Total findings triaged: {total}")
    lines.append("Priority distribution:")
    for p in range(5, 0, -1):
        count = by_priority.get(p, 0)
        if count:
            label = "CRITICAL" if p == 5 else "HIGH" if p == 4 else "MEDIUM" if p == 3 else "LOW" if p == 2 else "INFO"
            lines.append(f"  Priority {p} ({label}): {count}")
    lines.append("")
    
    # Source breakdown
    llm_count = sum(1 for r in results if r.source == "llm")
    baseline_count = sum(1 for r in results if r.source == "baseline")
    if llm_count and baseline_count:
        lines.append(f"Sources: {llm_count} LLM, {baseline_count} baseline")
        lines.append("")
    
    lines.append("-" * 70)
    lines.append("")
    
    # Sort by revised_priority desc, then original severity desc
    def sort_key(r: TriageResult) -> tuple:
        severity_rank = SEVERITY_ORDER.index(r.finding.severity)
        return (-r.revised_priority, severity_rank)
    
    sorted_results = sorted(results, key=sort_key)
    
    for i, result in enumerate(sorted_results, 1):
        finding = result.finding
        lines.append(f"#{i}  {finding.title}")
        lines.append(f"    Check: {finding.check} | Original Severity: {SEVERITY_LABEL[finding.severity]} | Revised Priority: {result.revised_priority}/5")
        lines.append(f"    Exploitability: {result.exploitability}/5")
        lines.append(f"    Source: {result.source} (prompt: {result.prompt_version})")
        lines.append("")
        lines.append(f"    Explanation: {result.explanation}")
        lines.append("")
        lines.append(f"    Fix: {result.fix}")
        lines.append("")
        snippet = finding.evidence.snippet
        display = snippet[:200] + ("..." if len(snippet) > 200 else "")
        lines.append(f"    Evidence: {display}")
        lines.append(f"    URL: {finding.evidence.url}")
        if finding.remediation:
            lines.append(f"    Scanner remediation: {finding.remediation}")
        lines.append("")
        lines.append("-" * 70)
        lines.append("")
    
    lines.append("=" * 70)
    lines.append("End of triage report")
    lines.append("=" * 70)
    
    return "\n".join(lines)


def write_report(results: list[TriageResult], filepath: str) -> None:
    """Write triage report to file."""
    report = generate_report(results)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(report)