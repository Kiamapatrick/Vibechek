import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from scipy.stats import spearmanr

from vibeshield.models.finding import Finding
from vibeshield.triage.models import TriageResult


@dataclass
class EvalResult:
    spearman_rho: float | None
    spearman_p: float | None
    mean_rubric_score: float | None
    pass_rate: float | None
    critical_failure_rate: float | None
    n_findings: int
    details: list[dict[str, Any]]


def load_golden(golden_path: Path) -> list[dict[str, Any]]:
    with golden_path.open("r", encoding="utf-8") as f:
        return json.load(f)  # type: ignore[no-any-return]


def load_triage_results(results_path: Path) -> list[TriageResult]:
    """Load TriageResult objects from a JSON file (list of TriageResult dicts)."""
    with results_path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    
    results: list[TriageResult] = []
    for item in data:
        finding_data = item["finding"]
        finding = Finding.from_dict(finding_data)
        results.append(TriageResult(
            finding=finding,
            explanation=item["explanation"],
            exploitability=item["exploitability"],
            fix=item["fix"],
            revised_priority=item["revised_priority"],
            source=item.get("source", "llm"),
            prompt_version=item.get("prompt_version", "v1"),
        ))
    return results


def compute_spearman(
    golden: list[dict[str, Any]],
    results: list[TriageResult],
) -> tuple[float | None, float | None]:
    """Compute Spearman rank correlation between human ranks and result priorities."""
    # Build mapping from finding_id -> human_rank
    human_ranks = {}
    for entry in golden:
        if entry.get("human_rank") is not None:
            human_ranks[entry["finding_id"]] = entry["human_rank"]
    
    if len(human_ranks) < 3:
        return None, None
    
    # Get result priorities in same order
    result_ranks = {}
    for r in results:
        if r.finding.id in human_ranks:
            result_ranks[r.finding.id] = r.revised_priority
    
    common_ids = set(human_ranks.keys()) & set(result_ranks.keys())
    if len(common_ids) < 3:
        return None, None
    
    human = [human_ranks[fid] for fid in sorted(common_ids)]
    model = [result_ranks[fid] for fid in sorted(common_ids)]
    
    try:
        rho, p = spearmanr(human, model)
        return float(rho), float(p)
    except (ValueError, RuntimeError):
        return None, None


def evaluate(
    golden_path: Path,
    llm_results_path: Path,
    baseline_results_path: Path | None = None,
) -> dict[str, Any]:
    """Run evaluation and return metrics dictionary."""
    golden = load_golden(golden_path)
    llm_results = load_triage_results(llm_results_path)
    
    # Spearman for LLM
    llm_rho, llm_p = compute_spearman(golden, llm_results)
    
    baseline_rho = baseline_p = None
    if baseline_results_path and baseline_results_path.exists():
        baseline_results = load_triage_results(baseline_results_path)
        baseline_rho, baseline_p = compute_spearman(golden, baseline_results)
    
    return {
        "llm": {
            "spearman_rho": llm_rho,
            "spearman_p": llm_p,
        },
        "baseline": {
            "spearman_rho": baseline_rho,
            "spearman_p": baseline_p,
        },
        "n_golden_with_ranks": sum(1 for g in golden if g.get("human_rank") is not None),
        "n_llm_results": len(llm_results),
        "note": "Rubric scoring is manual - not automated here",
    }


def main() -> None:
    import argparse
    
    parser = argparse.ArgumentParser(description="Evaluate triage results against golden set")
    parser.add_argument("--golden", default="src/vibeshield/triage/eval/golden.json")
    parser.add_argument("--llm-results", required=True)
    parser.add_argument("--baseline-results", default=None)
    parser.add_argument("--output", default="eval_results.json")
    
    args = parser.parse_args()
    
    metrics = evaluate(
        Path(args.golden),
        Path(args.llm_results),
        Path(args.baseline_results) if args.baseline_results else None,
    )
    
    with Path(args.output).open("w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    
    print("Evaluation complete.")
    print(f"  LLM Spearman ρ: {metrics['llm']['spearman_rho']}")
    print(f"  LLM p-value: {metrics['llm']['spearman_p']}")
    if metrics['baseline']['spearman_rho'] is not None:
        print(f"  Baseline Spearman ρ: {metrics['baseline']['spearman_rho']}")
        print(f"  Baseline p-value: {metrics['baseline']['spearman_p']}")
    print(f"  Results written to {args.output}")


if __name__ == "__main__":
    main()