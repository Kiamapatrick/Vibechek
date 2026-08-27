import json
import tempfile
from pathlib import Path

import pytest

from vibeshield.models.finding import Evidence, Finding, SeverityLevel
from vibeshield.triage.eval.harness import (
    compute_spearman,
    evaluate,
    load_golden,
    load_triage_results,
)
from vibeshield.triage.models import TriageResult


def _make_finding(finding_id: str, **overrides) -> Finding:
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
        "id": finding_id,
    }
    defaults.update(overrides)
    return Finding(**defaults)


def _make_triage_result(finding: Finding, revised_priority: int, source: str = "llm") -> TriageResult:
    return TriageResult(
        finding=finding,
        explanation=f"Explanation for {finding.title}",
        exploitability=4,
        fix=finding.remediation,
        revised_priority=revised_priority,
        source=source,
        prompt_version="v1",
    )


def _write_fixture(path: Path, results: list[TriageResult]) -> None:
    """Write TriageResult objects as JSON that load_triage_results can parse."""
    data = []
    for r in results:
        data.append({
            "finding": r.finding.to_dict(),
            "explanation": r.explanation,
            "exploitability": r.exploitability,
            "fix": r.fix,
            "revised_priority": r.revised_priority,
            "source": r.source,
            "prompt_version": r.prompt_version,
        })
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


class TestLoadGolden:
    def test_load_golden_valid(self, tmp_path):
        golden_data = [
            {"finding_id": "f1", "source": "synthetic", "human_rank": 1, "human_notes": "note1"},
            {"finding_id": "f2", "source": "real_scan", "human_rank": 2, "human_notes": "note2"},
            {"finding_id": "f3", "source": "synthetic", "human_rank": None, "human_notes": ""},
        ]
        path = tmp_path / "golden.json"
        with path.open("w", encoding="utf-8") as f:
            json.dump(golden_data, f)

        loaded = load_golden(path)

        assert len(loaded) == 3
        assert loaded[0]["finding_id"] == "f1"
        assert loaded[0]["human_rank"] == 1
        assert loaded[2]["human_rank"] is None

    def test_load_golden_missing_file(self, tmp_path):
        path = tmp_path / "nonexistent.json"
        with pytest.raises(FileNotFoundError):
            load_golden(path)

    def test_load_golden_malformed_json(self, tmp_path):
        path = tmp_path / "bad.json"
        path.write_text("not valid json {")
        with pytest.raises(json.JSONDecodeError):
            load_golden(path)

    def test_load_golden_missing_required_keys(self, tmp_path):
        golden_data = [
            {"finding_id": "f1", "source": "synthetic"},  # missing human_rank
            {"source": "real_scan", "human_rank": 1},  # missing finding_id
        ]
        path = tmp_path / "golden.json"
        with path.open("w", encoding="utf-8") as f:
            json.dump(golden_data, f)

        loaded = load_golden(path)
        assert len(loaded) == 2
        assert "human_rank" not in loaded[0]
        assert "finding_id" not in loaded[1]


class TestLoadTriageResults:
    def _make_fixture_file(self, tmp_path, results: list[TriageResult], name: str = "results.json") -> Path:
        path = tmp_path / name
        _write_fixture(path, results)
        return path

    def test_load_triage_results_valid(self, tmp_path):
        findings = [
            _make_finding("f1", title="Finding 1"),
            _make_finding("f2", title="Finding 2"),
        ]
        results = [
            _make_triage_result(findings[0], revised_priority=5),
            _make_triage_result(findings[1], revised_priority=3),
        ]
        path = self._make_fixture_file(tmp_path, results)

        loaded = load_triage_results(path)

        assert len(loaded) == 2
        assert loaded[0].finding.id == "f1"
        assert loaded[0].revised_priority == 5
        assert loaded[1].finding.id == "f2"
        assert loaded[1].revised_priority == 3
        assert loaded[0].source == "llm"
        assert loaded[1].source == "llm"

    def test_load_triage_results_missing_file(self, tmp_path):
        path = tmp_path / "nonexistent.json"
        with pytest.raises(FileNotFoundError):
            load_triage_results(path)

    def test_load_triage_results_malformed_json(self, tmp_path):
        path = tmp_path / "bad.json"
        path.write_text("not valid json {")
        with pytest.raises(json.JSONDecodeError):
            load_triage_results(path)

    def test_load_triage_results_missing_finding_key(self, tmp_path):
        path = tmp_path / "bad.json"
        with path.open("w", encoding="utf-8") as f:
            json.dump([{"explanation": "x", "exploitability": 1, "fix": "y", "revised_priority": 1}], f)

        with pytest.raises(ValueError, match="Missing 'finding' in result entry 0"):
            load_triage_results(path)

    def test_load_triage_results_missing_required_fields(self, tmp_path):
        finding = _make_finding("f1")
        path = tmp_path / "bad.json"
        with path.open("w", encoding="utf-8") as f:
            json.dump([{
                "finding": finding.to_dict(),
                "explanation": "x",
                "exploitability": 1,
                # missing "fix" and "revised_priority"
            }], f)

        with pytest.raises(ValueError, match="Missing required field 'fix' in result entry 0"):
            load_triage_results(path)

    def test_load_triage_results_invalid_source(self, tmp_path):
        finding = _make_finding("f1")
        path = tmp_path / "bad.json"
        # Write fixture with invalid source directly, bypassing TriageResult constructor
        with path.open("w", encoding="utf-8") as f:
            json.dump([{
                "finding": finding.to_dict(),
                "explanation": "x",
                "exploitability": 1,
                "fix": "y",
                "revised_priority": 1,
                "source": "invalid_source",
                "prompt_version": "v1",
            }], f)

        with pytest.raises(ValueError, match="source must be 'llm' or 'baseline'"):
            load_triage_results(path)

    def test_load_triage_results_not_a_list(self, tmp_path):
        path = tmp_path / "bad.json"
        with path.open("w", encoding="utf-8") as f:
            json.dump({"not": "a list"}, f)

        with pytest.raises(ValueError, match="Expected list of triage results"):
            load_triage_results(path)

    def test_load_triage_results_entry_not_object(self, tmp_path):
        path = tmp_path / "bad.json"
        with path.open("w", encoding="utf-8") as f:
            json.dump(["not an object"], f)

        with pytest.raises(ValueError, match="Result entry 0 is not an object"):
            load_triage_results(path)


class TestComputeSpearman:
    def _make_golden(self, entries: list[dict]) -> list[dict]:
        return entries

    def _make_results(self, finding_priorities: dict[str, int]) -> list[TriageResult]:
        results = []
        for fid, priority in finding_priorities.items():
            finding = _make_finding(fid)
            results.append(_make_triage_result(finding, priority))
        return results

    def test_fewer_than_3_ranked_returns_none(self):
        golden = [
            {"finding_id": "f1", "human_rank": 1},
            {"finding_id": "f2", "human_rank": 2},
        ]
        results = self._make_results({"f1": 1, "f2": 2})

        rho, p = compute_spearman(golden, results)

        assert rho is None
        assert p is None

    def test_perfect_agreement_rho_1(self):
        golden = [
            {"finding_id": "f1", "human_rank": 1},
            {"finding_id": "f2", "human_rank": 2},
            {"finding_id": "f3", "human_rank": 3},
            {"finding_id": "f4", "human_rank": 4},
            {"finding_id": "f5", "human_rank": 5},
        ]
        results = self._make_results({"f1": 1, "f2": 2, "f3": 3, "f4": 4, "f5": 5})

        rho, p = compute_spearman(golden, results)

        assert rho is not None
        assert abs(rho - 1.0) < 0.001
        assert p is not None
        assert p < 0.05

    def test_perfect_disagreement_rho_neg1(self):
        golden = [
            {"finding_id": "f1", "human_rank": 1},
            {"finding_id": "f2", "human_rank": 2},
            {"finding_id": "f3", "human_rank": 3},
            {"finding_id": "f4", "human_rank": 4},
            {"finding_id": "f5", "human_rank": 5},
        ]
        # Reverse order: highest human rank gets lowest model priority
        results = self._make_results({"f1": 5, "f2": 4, "f3": 3, "f4": 2, "f5": 1})

        rho, p = compute_spearman(golden, results)

        assert rho is not None
        assert abs(rho - (-1.0)) < 0.001
        assert p is not None
        assert p < 0.05

    def test_partial_overlap_excludes_missing_ids(self):
        golden = [
            {"finding_id": "f1", "human_rank": 1},
            {"finding_id": "f2", "human_rank": 2},
            {"finding_id": "f3", "human_rank": 3},
            {"finding_id": "f4", "human_rank": 4},
            {"finding_id": "f5", "human_rank": 5},
        ]
        # Results missing f4 and f5
        results = self._make_results({"f1": 1, "f2": 2, "f3": 3})

        rho, p = compute_spearman(golden, results)

        assert rho is not None
        assert abs(rho - 1.0) < 0.001

    def test_no_common_ids_returns_none(self):
        golden = [
            {"finding_id": "f1", "human_rank": 1},
            {"finding_id": "f2", "human_rank": 2},
            {"finding_id": "f3", "human_rank": 3},
        ]
        results = self._make_results({"f4": 1, "f5": 2, "f6": 3})

        rho, p = compute_spearman(golden, results)

        assert rho is None
        assert p is None

    def test_extra_golden_entries_without_rank_ignored(self):
        golden = [
            {"finding_id": "f1", "human_rank": 1},
            {"finding_id": "f2", "human_rank": 2},
            {"finding_id": "f3", "human_rank": 3},
            {"finding_id": "f4", "human_rank": None},  # no rank
            {"finding_id": "f5", "human_rank": None},  # no rank
        ]
        results = self._make_results({"f1": 1, "f2": 2, "f3": 3})

        rho, p = compute_spearman(golden, results)

        assert rho is not None
        assert abs(rho - 1.0) < 0.001

    def test_extra_result_entries_not_in_golden_ignored(self):
        golden = [
            {"finding_id": "f1", "human_rank": 1},
            {"finding_id": "f2", "human_rank": 2},
            {"finding_id": "f3", "human_rank": 3},
        ]
        results = self._make_results({"f1": 1, "f2": 2, "f3": 3, "f4": 4, "f5": 5})

        rho, p = compute_spearman(golden, results)

        assert rho is not None
        assert abs(rho - 1.0) < 0.001


class TestEvaluate:
    def _make_fixture_file(self, tmp_path, results: list[TriageResult], name: str) -> Path:
        path = tmp_path / name
        _write_fixture(path, results)
        return path

    def _make_golden_file(self, tmp_path, entries: list[dict], name: str = "golden.json") -> Path:
        path = tmp_path / name
        with path.open("w", encoding="utf-8") as f:
            json.dump(entries, f)
        return path

    def test_evaluate_llm_only(self, tmp_path):
        golden = [
            {"finding_id": "f1", "human_rank": 1},
            {"finding_id": "f2", "human_rank": 2},
            {"finding_id": "f3", "human_rank": 3},
        ]
        findings = [_make_finding(f) for f in ["f1", "f2", "f3"]]
        llm_results = [
            _make_triage_result(findings[0], 1),
            _make_triage_result(findings[1], 2),
            _make_triage_result(findings[2], 3),
        ]

        golden_path = self._make_golden_file(tmp_path, golden)
        llm_path = self._make_fixture_file(tmp_path, llm_results, "llm.json")

        metrics = evaluate(golden_path, llm_path)

        assert "llm" in metrics
        assert "baseline" in metrics
        assert metrics["llm"]["spearman_rho"] is not None
        assert abs(metrics["llm"]["spearman_rho"] - 1.0) < 0.001
        assert metrics["baseline"]["spearman_rho"] is None
        assert metrics["baseline"]["spearman_p"] is None
        assert metrics["n_golden_with_ranks"] == 3
        assert metrics["n_llm_results"] == 3
        assert metrics["note"] == "Rubric scoring is manual - not automated here"

    def test_evaluate_with_baseline(self, tmp_path):
        golden = [
            {"finding_id": "f1", "human_rank": 1},
            {"finding_id": "f2", "human_rank": 2},
            {"finding_id": "f3", "human_rank": 3},
        ]
        findings = [_make_finding(f) for f in ["f1", "f2", "f3"]]
        llm_results = [
            _make_triage_result(findings[0], 1),
            _make_triage_result(findings[1], 2),
            _make_triage_result(findings[2], 3),
        ]
        baseline_results = [
            _make_triage_result(findings[0], 3, source="baseline"),
            _make_triage_result(findings[1], 2, source="baseline"),
            _make_triage_result(findings[2], 1, source="baseline"),
        ]

        golden_path = self._make_golden_file(tmp_path, golden)
        llm_path = self._make_fixture_file(tmp_path, llm_results, "llm.json")
        baseline_path = self._make_fixture_file(tmp_path, baseline_results, "baseline.json")

        metrics = evaluate(golden_path, llm_path, baseline_path)

        assert metrics["llm"]["spearman_rho"] is not None
        assert abs(metrics["llm"]["spearman_rho"] - 1.0) < 0.001
        assert metrics["baseline"]["spearman_rho"] is not None
        assert abs(metrics["baseline"]["spearman_rho"] - (-1.0)) < 0.001

    def test_evaluate_baseline_path_none(self, tmp_path):
        golden = [
            {"finding_id": "f1", "human_rank": 1},
            {"finding_id": "f2", "human_rank": 2},
            {"finding_id": "f3", "human_rank": 3},
        ]
        findings = [_make_finding(f) for f in ["f1", "f2", "f3"]]
        llm_results = [_make_triage_result(f, i+1) for i, f in enumerate(findings)]

        golden_path = self._make_golden_file(tmp_path, golden)
        llm_path = self._make_fixture_file(tmp_path, llm_results, "llm.json")

        metrics = evaluate(golden_path, llm_path, baseline_results_path=None)

        assert metrics["baseline"]["spearman_rho"] is None

    def test_evaluate_baseline_path_not_exists(self, tmp_path):
        golden = [
            {"finding_id": "f1", "human_rank": 1},
            {"finding_id": "f2", "human_rank": 2},
            {"finding_id": "f3", "human_rank": 3},
        ]
        findings = [_make_finding(f) for f in ["f1", "f2", "f3"]]
        llm_results = [_make_triage_result(f, i+1) for i, f in enumerate(findings)]

        golden_path = self._make_golden_file(tmp_path, golden)
        llm_path = self._make_fixture_file(tmp_path, llm_results, "llm.json")
        baseline_path = tmp_path / "nonexistent.json"

        metrics = evaluate(golden_path, llm_path, baseline_path)

        assert metrics["baseline"]["spearman_rho"] is None

    def test_evaluate_returns_expected_dict_shape(self, tmp_path):
        golden = [
            {"finding_id": "f1", "human_rank": 1},
            {"finding_id": "f2", "human_rank": 2},
            {"finding_id": "f3", "human_rank": 3},
        ]
        findings = [_make_finding(f) for f in ["f1", "f2", "f3"]]
        llm_results = [_make_triage_result(f, i+1) for i, f in enumerate(findings)]

        golden_path = self._make_golden_file(tmp_path, golden)
        llm_path = self._make_fixture_file(tmp_path, llm_results, "llm.json")

        metrics = evaluate(golden_path, llm_path)

        expected_keys = {"llm", "baseline", "n_golden_with_ranks", "n_llm_results", "note"}
        assert set(metrics.keys()) == expected_keys
        assert set(metrics["llm"].keys()) == {"spearman_rho", "spearman_p"}
        assert set(metrics["baseline"].keys()) == {"spearman_rho", "spearman_p"}

    def test_evaluate_counts_n_golden_with_ranks(self, tmp_path):
        golden = [
            {"finding_id": "f1", "human_rank": 1},
            {"finding_id": "f2", "human_rank": 2},
            {"finding_id": "f3", "human_rank": None},
            {"finding_id": "f4", "human_rank": 3},
            {"finding_id": "f5", "human_rank": None},
        ]
        findings = [_make_finding(f) for f in ["f1", "f2", "f3", "f4", "f5"]]
        llm_results = [_make_triage_result(f, i+1) for i, f in enumerate(findings)]

        golden_path = self._make_golden_file(tmp_path, golden)
        llm_path = self._make_fixture_file(tmp_path, llm_results, "llm.json")

        metrics = evaluate(golden_path, llm_path)

        assert metrics["n_golden_with_ranks"] == 3


class TestMainCLI:
    def test_main_requires_llm_results(self):
        import sys
        from unittest.mock import patch

        with patch.object(sys, "argv", ["harness.py", "--golden", "golden.json"]):
            with pytest.raises(SystemExit) as exc_info:
                from vibeshield.triage.eval.harness import main
                main()
            assert exc_info.value.code != 0

    def test_main_default_golden_path(self):
        import sys
        from unittest.mock import patch, MagicMock

        with patch.object(sys, "argv", ["harness.py", "--llm-results", "llm.json"]):
            with patch("vibeshield.triage.eval.harness.evaluate") as mock_evaluate:
                mock_evaluate.return_value = {
                    "llm": {"spearman_rho": 0.5, "spearman_p": 0.1},
                    "baseline": {"spearman_rho": None, "spearman_p": None},
                    "n_golden_with_ranks": 3,
                    "n_llm_results": 3,
                    "note": "test",
                }
                with patch("builtins.open", MagicMock()):
                    with patch("json.dump") as mock_dump:
                        with patch("builtins.print"):
                            from vibeshield.triage.eval.harness import main
                            main()
                            mock_evaluate.assert_called_once()
                            call_args = mock_evaluate.call_args
                            assert str(call_args[0][0]).endswith("golden.json")

    def test_main_output_written(self, tmp_path):
        import sys
        from unittest.mock import patch, MagicMock

        output_path = tmp_path / "eval_results.json"
        with patch.object(sys, "argv", [
            "harness.py", "--llm-results", "llm.json", "--output", str(output_path)
        ]):
            with patch("vibeshield.triage.eval.harness.evaluate") as mock_evaluate:
                mock_evaluate.return_value = {
                    "llm": {"spearman_rho": 0.5, "spearman_p": 0.1},
                    "baseline": {"spearman_rho": None, "spearman_p": None},
                    "n_golden_with_ranks": 3,
                    "n_llm_results": 3,
                    "note": "test",
                }
                with patch("builtins.print"):
                    from vibeshield.triage.eval.harness import main
                    main()
                    assert output_path.exists()
                    with output_path.open("r") as f:
                        data = json.load(f)
                    assert data["llm"]["spearman_rho"] == 0.5