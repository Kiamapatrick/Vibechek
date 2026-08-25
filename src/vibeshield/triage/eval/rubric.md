# Qualitative Rubric for Triage Evaluation

Apply to each finding in the golden set. Score each question 0 / 1 / 2.

## Question 1: Root Cause Accuracy
**Does the explanation correctly identify the root cause matching the finding's WSTG/ATT&CK tag and evidence?**

| Score | Description |
|-------|-------------|
| 0 | Explanation is wrong, generic, or describes a different vulnerability class |
| 1 | Partially correct but misses key aspect or conflates with related issue |
| 2 | Precisely identifies the root cause; references specific evidence (snippet, matched pattern, header) and correct WSTG/ATT&CK mapping |

## Question 2: Fix Specificity & Technical Correctness
**Is the fix specific and technically correct — not generic "improve your security" filler?**

| Score | Description |
|-------|-------------|
| 0 | Generic advice ("improve security", "add protection", "follow best practices") or technically incorrect |
| 1 | Directionally correct but vague (e.g., "enable RLS" without table/policy details) |
| 2 | Specific, actionable, and technically accurate: names exact config setting, dashboard location, code pattern, or SQL policy |

## Question 3: Exploitability Realism
**Is the stated exploitability realistic given the actual evidence, not exaggerated?**

| Score | Description |
|-------|-------------|
| 0 | Clearly wrong: rates theoretical risk as trivial, or trivial risk as theoretical |
| 1 | Roughly in the right ballpark but not well justified by evidence |
| 2 | Exploitability score (1-5) is well-calibrated to the evidence: references specific snippet/pattern/header that justifies the rating |

---

## Scoring

Per finding: 0-6 points (sum of three questions)

| Total | Assessment |
|-------|------------|
| 0-2 | Poor — explanation unreliable |
| 3-4 | Acceptable — useful but with gaps |
| 5-6 | Excellent — trustworthy for decision-making |

## Aggregate Metrics

- **Mean rubric score** across golden set (max 6.0)
- **Pass rate**: % of findings scoring ≥4
- **Critical failure rate**: % of findings scoring 0 on any question

---

## Usage Notes

1. Score each finding independently — don't let one finding's score influence another
2. If unsure between 1 and 2, default to 1 (conservative)
3. Record brief justification for each score in eval results for auditability
4. The same human should score both LLM and baseline outputs for fair comparison