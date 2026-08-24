import pytest

from vibeshield.models.finding import SeverityLevel
from vibeshield.scanner.scoring import (
    calculate_severity,
    get_impact_description,
    get_likelihood_description,
    get_severity_consequence,
)


class TestScoring:
    def test_critical_severity(self):
        severity, score = calculate_severity(5, 5)
        assert severity == SeverityLevel.CRITICAL
        assert score == 25

    def test_high_severity(self):
        severity, score = calculate_severity(4, 4)
        assert severity == SeverityLevel.HIGH
        assert score == 16

    def test_medium_severity(self):
        severity, score = calculate_severity(3, 3)
        assert severity == SeverityLevel.MEDIUM
        assert score == 9

    def test_low_severity(self):
        severity, score = calculate_severity(2, 2)
        assert severity == SeverityLevel.LOW
        assert score == 4

    def test_info_severity(self):
        severity, score = calculate_severity(1, 1)
        assert severity == SeverityLevel.INFO
        assert score == 1

    def test_boundary_critical_high(self):
        severity, score = calculate_severity(4, 5)
        assert severity == SeverityLevel.CRITICAL
        assert score == 20

    def test_boundary_high_medium(self):
        severity, score = calculate_severity(3, 4)
        assert severity == SeverityLevel.HIGH
        assert score == 12

    def test_boundary_medium_low(self):
        severity, score = calculate_severity(2, 3)
        assert severity == SeverityLevel.MEDIUM
        assert score == 6

    def test_boundary_low_info(self):
        severity, score = calculate_severity(1, 2)
        assert severity == SeverityLevel.INFO
        assert score == 2

    def test_invalid_impact(self):
        with pytest.raises(ValueError):
            calculate_severity(0, 3)
        with pytest.raises(ValueError):
            calculate_severity(6, 3)

    def test_invalid_likelihood(self):
        with pytest.raises(ValueError):
            calculate_severity(3, 0)
        with pytest.raises(ValueError):
            calculate_severity(3, 6)

    def test_consequence_strings(self):
        assert "Immediate action" in get_severity_consequence(SeverityLevel.CRITICAL)
        assert "Urgent fix" in get_severity_consequence(SeverityLevel.HIGH)
        assert "Should fix soon" in get_severity_consequence(SeverityLevel.MEDIUM)
        assert "Fix when convenient" in get_severity_consequence(SeverityLevel.LOW)
        assert "Informational" in get_severity_consequence(SeverityLevel.INFO)

    def test_impact_descriptions(self):
        assert "No direct" in get_impact_description(1)
        assert "PII" in get_impact_description(2)
        assert "Authentication tokens" in get_impact_description(3)
        assert "Full database read" in get_impact_description(4)
        assert "Full database write" in get_impact_description(5)

    def test_likelihood_descriptions(self):
        assert "Theoretical" in get_likelihood_description(1)
        assert "authenticated" in get_likelihood_description(2)
        assert "complex" in get_likelihood_description(3)
        assert "trivial" in get_likelihood_description(4)
        assert "Automatable" in get_likelihood_description(5)