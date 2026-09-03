from pathlib import Path

from vibeshield.triage.ingest import load_report
from vibeshield.triage.orchestrator import run_triage
from vibeshield.triage.report import generate_report


def run_full_pipeline(scan_report_path: Path) -> str:
    """Ingest a scan report, triage every finding, return the formatted report."""
    findings = load_report(scan_report_path)
    results = run_triage(findings)
    return generate_report(results)