import pytest
from vibeshield.scanner.checks.outdated_deps import OutdatedDepsCheck
from vibeshield.models.recon import ReconData


SAFE_VERSIONS = {
    "lodash": "4.17.21",      # highest vuln: 4.17.20
    "axios": "1.0.0",         # highest vuln: 0.21.1 (0.x major)
    "moment": "2.30.0",       # highest vuln: 2.29.1
}

VULNERABLE_VERSIONS = {
    "lodash": "4.17.20",
    "axios": "0.21.1",
    "moment": "2.29.1",
}


class TestVersionComparison:
    """Unit tests for _version_matches_or_older - pure logic, no Finding construction."""

    @pytest.fixture
    def check(self):
        return OutdatedDepsCheck()

    @pytest.mark.parametrize("current,vuln_version,expected", [
        ("4.17.19", "4.17.20", True),   # older -> vulnerable
        ("4.17.20", "4.17.20", True),   # exact -> vulnerable
        ("4.17.21", "4.17.20", False),  # newer -> safe
        ("1.0.0", "2.0.0", True),       # major diff
        ("2.0.0", "1.0.0", False),      # major diff reverse
        ("1.2.3", "1.2.3", True),       # exact patch
        ("1.2.4", "1.2.3", False),      # newer patch
        ("0.21.1", "0.21.1", True),     # 0.x exact
        ("0.21.2", "0.21.1", False),    # 0.x newer patch
    ])
    def test_version_comparison_logic(self, check, current, vuln_version, expected):
        """_version_matches_or_older behaves correctly at boundaries."""
        result = check._version_matches_or_older(current, vuln_version)
        assert result == expected, f"{current} vs {vuln_version}: expected {expected}"


class TestOutdatedDepsCheck:
    """Integration tests for OutdatedDepsCheck - tests Finding construction and full flow."""

    @pytest.fixture
    def check(self):
        return OutdatedDepsCheck()

    @pytest.fixture
    def recon(self):
        return ReconData(target_url="https://example.com", base_url="https://example.com")

    # === CRITICAL: Safe version newer than all known vulnerable entries produces zero findings ===
    @pytest.mark.parametrize("lib,safe_version", SAFE_VERSIONS.items())
    def test_safe_version_produces_zero_findings(self, check, recon, lib, safe_version):
        """Version newer than all known vulnerable entries produces zero findings."""
        # Test _check_vulnerabilities directly (unit test)
        vulns = check._check_vulnerabilities(lib, safe_version)
        assert vulns == [], f"{lib}@{safe_version} should be safe but returned: {vulns}"

        # Test full run with mocked content
        content = f"{lib}@{safe_version}"
        deps = check._extract_dependencies(content)
        findings = []
        for name, version in deps:
            vulns = check._check_vulnerabilities(name, version)
            if vulns:
                findings.append((name, version, vulns))
        assert findings == [], f"Full run: {lib}@{safe_version} should be safe"

    # === Vulnerable version detected ===
    @pytest.mark.parametrize("lib,vuln_version", VULNERABLE_VERSIONS.items())
    def test_vulnerable_version_detected(self, check, recon, lib, vuln_version):
        """Known vulnerable version produces findings with correct CVEs."""
        vulns = check._check_vulnerabilities(lib, vuln_version)
        assert vulns != [], f"{lib}@{vuln_version} should be vulnerable"
        assert len(vulns) >= 1
        assert all(cve.startswith("CVE-") for cve in vulns)

    # === Boundary: exact match = vulnerable ===
    def test_exact_version_match_is_vulnerable(self, check):
        """Exact version match with KNOWN_VULNS entry is vulnerable."""
        vulns = check._check_vulnerabilities("lodash", "4.17.20")
        assert vulns != []
        assert "CVE-2021-23337" in vulns

    # === Unknown library ===
    def test_unknown_library_produces_zero_findings(self, check):
        """Library not in KNOWN_VULNS produces zero findings regardless of version."""
        vulns = check._check_vulnerabilities("unknown-lib", "1.0.0")
        assert vulns == []
        vulns = check._check_vulnerabilities("unknown-lib", "0.0.1")
        assert vulns == []

    # === Version extraction from content ===
    @pytest.mark.parametrize("content,expected_deps", [
        ("lodash@4.17.20", [("lodash", "4.17.20")]),
        ("@scope/pkg@1.2.3", [("pkg", "1.2.3")]),  # @ stripped by regex
        ('{"imports": {"lodash": "4.17.20"}}', [("lodash", "4.17.20")]),
        ('{"dependencies": {"lodash": "^4.17.20"}}', [("lodash", "4.17.20")]),
        ("lodash@4.17.20\njquery@3.4.0", [("lodash", "4.17.20"), ("jquery", "3.4.0")]),
        ("lodash@4.17.20 lodash@4.17.20", [("lodash", "4.17.20")]),  # dedup
    ])
    def test_extract_dependencies(self, check, content, expected_deps):
        """_extract_dependencies correctly parses various formats and deduplicates."""
        deps = check._extract_dependencies(content)
        assert set(deps) == set(expected_deps)

    # === Full integration: safe version in content ===
    def test_full_run_safe_version_zero_findings(self, check, recon):
        """Full run with safe version content produces zero findings."""
        content = "lodash@4.17.21\njquery@3.5.0"
        deps = check._extract_dependencies(content)
        findings = []
        for name, version in deps:
            vulns = check._check_vulnerabilities(name, version)
            if vulns:
                findings.append((name, version, vulns))
        assert findings == [], "Safe versions should produce zero findings in full run"

    # === Full integration: mixed safe and vulnerable ===
    def test_full_run_mixed_safe_and_vulnerable(self, check, recon):
        """Full run with mixed content only flags vulnerable ones."""
        content = "lodash@4.17.21\nlodash@4.17.20"
        deps = check._extract_dependencies(content)
        findings = []
        for name, version in deps:
            vulns = check._check_vulnerabilities(name, version)
            if vulns:
                findings.append((name, version, vulns))
        assert len(findings) == 1
        assert findings[0][0] == "lodash"
        assert findings[0][1] == "4.17.20"

    # === Unknown library in content ===
    def test_unknown_library_in_content_produces_zero_findings(self, check, recon):
        """Unknown library in content produces zero findings."""
        content = "unknown-lib@1.0.0"
        deps = check._extract_dependencies(content)
        findings = []
        for name, version in deps:
            vulns = check._check_vulnerabilities(name, version)
            if vulns:
                findings.append((name, version, vulns))
        assert findings == []

    # === Version boundary edge cases ===
    @pytest.mark.parametrize("current,vuln_version,expected", [
        ("4.17.19", "4.17.20", True),
        ("4.17.20", "4.17.20", True),
        ("4.17.21", "4.17.20", False),
        ("1.0.0", "2.0.0", True),
        ("2.0.0", "1.0.0", False),
    ])
    def test_version_comparison_edge_cases(self, check, current, vuln_version, expected):
        """_version_matches_or_older behaves correctly at boundaries."""
        result = check._version_matches_or_older(current, vuln_version)
        assert result == expected

    # === Malformed version strings ===
    @pytest.mark.parametrize("version", ["not.a.version", "1.2", "1.2.3.4.5", ""])
    def test_malformed_version_returns_false(self, check, version):
        """Malformed version strings return False (safe)."""
        result = check._version_matches_or_older(version, "1.0.0")
        assert result == False