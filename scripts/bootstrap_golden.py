#!/usr/bin/env python3
"""Bootstrap golden.json from a real scan report.

Usage:
    python scripts/bootstrap_golden.py path/to/report.json

Reads a JSON report, extracts finding IDs, and updates golden.json
with real_scan entries (preserving any existing synthetic entries).
Human_rank and human_notes are left as null/empty for manual labeling.
"""

import json
import sys
from pathlib import Path

from vibeshield.triage.ingest import load_report


def main() -> None:
    if len(sys.argv) != 2:
        print("Usage: python scripts/bootstrap_golden.py <report.json>", file=sys.stderr)
        sys.exit(1)
    
    report_path = Path(sys.argv[1])
    if not report_path.exists():
        print(f"Report not found: {report_path}", file=sys.stderr)
        sys.exit(1)
    
    findings = load_report(report_path)
    
    golden_path = Path(__file__).parent.parent / "vibeshield" / "triage" / "eval" / "golden.json"
    
    # Load existing golden.json to preserve synthetic entries
    existing = []
    if golden_path.exists():
        with golden_path.open("r", encoding="utf-8") as f:
            existing = json.load(f)
    
    # Keep synthetic entries
    synthetic_entries = [e for e in existing if e.get("source") == "synthetic"]
    
    # Build new real_scan entries from report
    real_entries = []
    for finding in findings:
        real_entries.append({
            "finding_id": finding.id,
            "source": "real_scan",
            "human_rank": None,
            "human_notes": "",
        })
    
    # Combine: real entries first, then synthetic
    combined = real_entries + synthetic_entries
    
    # Write back
    with golden_path.open("w", encoding="utf-8") as f:
        json.dump(combined, f, indent=2)
    
    print(f"Updated {golden_path}")
    print(f"  Real scan entries: {len(real_entries)}")
    print(f"  Synthetic entries preserved: {len(synthetic_entries)}")
    print("\nNext step: Edit golden.json and fill in human_rank (1-N) and human_notes for each entry.")


if __name__ == "__main__":
    main()