#!/usr/bin/env python3
"""Live Groq API smoke test for triage pipeline.

Run with: GROQ_API_KEY=xxx python scripts/smoke_test_llm.py

Exit codes:
  0 = all findings valid, no systematic calibration drift
  1 = setup failure (missing key, import error, KB load failure)
  2 = validation failure (bad JSON, missing field, exploitability not in 1-5)
  3 = systematic calibration drift (2+ findings same sign: all higher OR all lower)
  4 = exhausted retries on one+ findings (Groq rate limit/timeout after max retries)
"""

import os
import re
import sys
from typing import Any

from vibeshield.models.finding import Evidence, Finding, SeverityLevel
from vibeshield.triage.context.retriever import get_retriever
from vibeshield.triage.llm.client import GroqClient
from vibeshield.triage.models import ContextSnippet

KB_KEY_TERMS = {
    "supabase_firebase": ["RLS", "anon key", "Row Level Security", "Supabase Dashboard"],
    "cors": ["ACAO", "ACAC", "origin allowlist", "credentials"],
    "rate_limiting": ["rate limit", "Retry-After", "429", "credential stuffing"],
    "security_headers": ["CSP", "Content-Security-Policy", "HSTS", "X-Frame-Options"],
    "exposed_secrets": ["rotate", "IAM", "server-side", "environment variable"],
    "debug_mode": ["debug", "production", "stack trace", "error detail"],
    "outdated_deps": ["CVE", "vulnerable", "upgrade", "patched version"],
    "unprotected_routes": ["authentication", "middleware", "guard", "protected route"],
}

CAPITALIZED_PHRASE_RE = re.compile(r"\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+\b")
ACRONYM_RE = re.compile(r"\b[A-Z]{2,}\b")


def extract_kb_terms(content: str, topic: str) -> list[str]:
    """Extract distinctive terms from KB content + hand-picked list."""
    terms = set()
    terms.update(CAPITALIZED_PHRASE_RE.findall(content))
    terms.update(ACRONYM_RE.findall(content))
    terms.update(KB_KEY_TERMS.get(topic, []))
    return sorted(terms)


def check_kb_terms_in_output(output_text: str, terms: list[str]) -> int:
    """Count how many extracted KB terms appear in model output (case-insensitive)."""
    output_lower = output_text.lower()
    count = 0
    for term in terms:
        if term.lower() in output_lower:
            count += 1
    return count


def make_finding(check: str, title: str, snippet: str, wstg_id: str, attck_ids: list[str], severity: SeverityLevel) -> Finding:
    return Finding(
        check=check,
        title=title,
        severity=severity,
        score=16 if severity != SeverityLevel.CRITICAL else 20,
        impact=4 if severity != SeverityLevel.CRITICAL else 5,
        likelihood=4,
        wstg_id=wstg_id,
        attck_ids=attck_ids,
        evidence=Evidence(url="https://example.com/test", snippet=snippet),
        confidence=0.9,
        remediation="Test remediation",
        references=["https://example.com"],
    )


TEST_CASES: list[dict[str, Any]] = [
    {
        "name": "exposed_secrets",
        "tier": "Critical",
        "finding": lambda: make_finding(
            check="exposed_secrets",
            title="Exposed AWS Key in JS Bundle",
            snippet='const AWS_KEY = "AKIA..."',
            wstg_id="WSTG-INFO-02",
            attck_ids=["T1552.001"],
            severity=SeverityLevel.CRITICAL,
        ),
        "expected_expl": {4, 5},
        "expected_pri": {4, 5},
        "use_kb": False,
    },
    {
        "name": "supabase_firebase",
        "tier": "High",
        "finding": lambda: make_finding(
            check="supabase_firebase",
            title="RLS Bypass on Users Table",
            snippet="GET /rest/v1/users returned data without authentication",
            wstg_id="WSTG-ATHZ-02",
            attck_ids=["T1213"],
            severity=SeverityLevel.HIGH,
        ),
        "expected_expl": {3, 4, 5},
        "expected_pri": {3, 4, 5},
        "use_kb": True,
    },
    {
        "name": "cors",
        "tier": "High",
        "finding": lambda: make_finding(
            check="cors",
            title="CORS Origin Reflection with Credentials",
            snippet="Access-Control-Allow-Origin: https://evil.com Access-Control-Allow-Credentials: true",
            wstg_id="WSTG-CONF-06",
            attck_ids=["T1190"],
            severity=SeverityLevel.HIGH,
        ),
        "expected_expl": {3, 4, 5},
        "expected_pri": {3, 4, 5},
        "use_kb": False,
    },
    {
        "name": "security_headers",
        "tier": "Low",
        "finding": lambda: make_finding(
            check="security_headers",
            title="Missing CSP Header on Static Page",
            snippet="Content-Security-Policy header missing on /about.html",
            wstg_id="WSTG-CONF-12",
            attck_ids=[],
            severity=SeverityLevel.LOW,
        ),
        "expected_expl": {1, 2},
        "expected_pri": {1, 2, 3},
        "use_kb": False,
    },
]


def run_finding_twice(client: GroqClient, finding: Finding, context: list[ContextSnippet]) -> list[dict[str, Any]]:
    """Run generate() twice, return list of parsed results."""
    results = []
    for _ in range(2):
        result = client.generate(finding, context=context)
        results.append({
            "explanation": result.explanation,
            "exploitability": result.exploitability,
            "fix": result.fix,
            "revised_priority": result.revised_priority,
        })
    return results


def check_consistency(runs: list[dict[str, Any]]) -> tuple[bool, str]:
    """Check if exploitability and revised_priority match across two runs."""
    r1, r2 = runs[0], runs[1]
    expl_same = r1["exploitability"] == r2["exploitability"]
    pri_same = r1["revised_priority"] == r2["revised_priority"]
    expl_msg = "same OK" if expl_same else f"DIFFERENT ({r1['exploitability']} vs {r2['exploitability']}) FAIL"
    pri_msg = "same OK" if pri_same else f"DIFFERENT ({r1['revised_priority']} vs {r2['revised_priority']}) FAIL"
    msg = f"Delta exploitability: {expl_msg}, revised_priority: {pri_msg}"
    return expl_same and pri_same, msg


def check_calibration(runs: list[dict[str, Any]], expected_expl: set[int], expected_pri: set[int]) -> tuple[str, int]:
    """Check calibration. Returns (status_msg, sign) where sign: +1=higher, -1=lower, 0=in_range."""
    expl = runs[0]["exploitability"]
    pri = runs[0]["revised_priority"]

    expl_in = expl in expected_expl
    pri_in = pri in expected_pri

    if expl_in and pri_in:
        return f"PASS (exploitability in {sorted(expected_expl)}, revised_priority in {sorted(expected_pri)})", 0

    expl_sign = 0
    if expl < min(expected_expl):
        expl_sign = -1
    elif expl > max(expected_expl):
        expl_sign = +1

    pri_sign = 0
    if pri < min(expected_pri):
        pri_sign = -1
    elif pri > max(expected_pri):
        pri_sign = +1

    sign = expl_sign if expl_sign != 0 else pri_sign
    direction = "higher" if sign > 0 else "lower"
    return f"expected expl in {sorted(expected_expl)} pri in {sorted(expected_pri)}, got expl={expl} pri={pri} -- OUTSIDE ({direction}) (informational)", sign


def main() -> int:
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        print("ERROR: GROQ_API_KEY not set in environment", file=sys.stderr)
        return 1

    try:
        client = GroqClient(api_key=api_key)
        retriever = get_retriever()
    except (ValueError, RuntimeError) as e:
        print(f"ERROR: Setup failed: {e}", file=sys.stderr)
        return 1

    validation_failures = 0
    calibration_signs = []
    calibration_passes = 0
    consistency_passes = 0
    kb_term_counts = []
    retry_exhausted_count = 0
    first_finding_retry_exhausted = False

    print("=== SMOKE TEST: Groq Live Integration ===\n")

    for idx, tc in enumerate(TEST_CASES, 1):
        finding = tc["finding"]()
        context = []

        if tc["use_kb"]:
            try:
                snippets = retriever.retrieve(finding, k=3)
                context = snippets
                kb_terms = extract_kb_terms("\n".join(s.content for s in snippets), finding.check)
            except (ValueError, RuntimeError, OSError) as e:
                print(f"Finding {idx}/5: {tc['name']} ({tc['tier']}) — KB retrieval failed: {e}")
                kb_terms = []
        else:
            kb_terms = []

        print(f"Finding {idx}/5: {tc['name']} ({tc['tier']})" + (" — with KB context" if tc["use_kb"] else ""))

        try:
            runs = run_finding_twice(client, finding, context)
        except (RuntimeError, ValueError, OSError) as e:
            if "RetryError" in type(e).__name__ or "max retries" in str(e).lower():
                retry_exhausted_count += 1
                if idx == 1:
                    first_finding_retry_exhausted = True
                print(f"  RETRY EXHAUSTED: {e}")
                continue
            else:
                print(f"  ERROR: {e}")
                validation_failures += 1
                continue

        for run_idx, run in enumerate(runs, 1):
            if not all(k in run for k in ("explanation", "exploitability", "fix", "revised_priority")):
                print(f"  Run {run_idx}: MISSING REQUIRED FIELD")
                validation_failures += 1
                continue
            if not isinstance(run["exploitability"], int) or not (1 <= run["exploitability"] <= 5):
                print(f"  Run {run_idx}: INVALID EXPLOITABILITY {run['exploitability']}")
                validation_failures += 1
                continue
            if not isinstance(run["revised_priority"], int) or not (1 <= run["revised_priority"] <= 5):
                print(f"  Run {run_idx}: INVALID REVISED_PRIORITY {run['revised_priority']}")
                validation_failures += 1
                continue
            print(f"  Run {run_idx}: exploitability={run['exploitability']}, revised_priority={run['revised_priority']}")

        if len(runs) == 2:
            consistent, msg = check_consistency(runs)
            print(f"  {msg}")
            if consistent:
                consistency_passes += 1

            cal_msg, sign = check_calibration(runs, tc["expected_expl"], tc["expected_pri"])
            print(f"  Calibration: {cal_msg}")
            if sign != 0:
                calibration_signs.append(sign)
            else:
                calibration_passes += 1

            if tc["use_kb"] and kb_terms:
                output_text = runs[0]["explanation"] + " " + runs[0]["fix"]
                matched = check_kb_terms_in_output(output_text, kb_terms)
                print(f"  KB terms referenced: {matched}/{len(kb_terms)} (informational)")
                kb_term_counts.append((matched, len(kb_terms)))

        print()

    print("SUMMARY:")
    print(f"  Valid JSON: {len(TEST_CASES) - validation_failures}/{len(TEST_CASES)}")
    print(f"  Consistency: {consistency_passes}/{len(TEST_CASES)}")
    print(f"  Calibration PASS: {calibration_passes}/{len(TEST_CASES)}")
    if kb_term_counts:
        total_matched = sum(m for m, _ in kb_term_counts)
        total_terms = sum(t for _, t in kb_term_counts)
        print(f"  KB terms referenced: {total_matched}/{total_terms} (informational)")

    if retry_exhausted_count > 0:
        if first_finding_retry_exhausted:
            print(f"  Retry exhausted: {retry_exhausted_count} finding(s) (first finding exhausted — possible systemic Groq issue)")
        else:
            print(f"  Retry exhausted: {retry_exhausted_count} finding(s)")

    if validation_failures > 0:
        return 2

    positive_signs = sum(1 for s in calibration_signs if s > 0)
    negative_signs = sum(1 for s in calibration_signs if s < 0)
    if positive_signs >= 2 or negative_signs >= 2:
        return 3

    if retry_exhausted_count > 0:
        return 4

    return 0


if __name__ == "__main__":
    sys.exit(main())