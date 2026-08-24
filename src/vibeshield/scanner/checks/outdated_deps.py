from vibeshield.models.finding import Evidence, Finding, SeverityLevel
from vibeshield.models.recon import ReconData
from vibeshield.scanner.checks.base import BaseCheck
from vibeshield.scanner.scoring import calculate_severity
from vibeshield.scanner.tagging import apply_tags_to_findings
from vibeshield.utils.http import HTTPClient
from vibeshield.utils.patterns import VERSION_PATTERNS


class OutdatedDepsCheck(BaseCheck):
    name = "outdated_deps"
    description = "Detects client-side libraries with known CVEs via version fingerprinting"
    wstg_id = ""
    attck_ids = []

    KNOWN_VULNS = {
        "lodash": {
            "4.17.20": ["CVE-2021-23337", "CVE-2020-28500"],
            "4.17.19": ["CVE-2020-28500"],
            "4.17.15": ["CVE-2019-10744", "CVE-2019-1010266"],
        },
        "jquery": {
            "3.4.0": ["CVE-2019-11358"],
            "3.3.1": ["CVE-2019-11358", "CVE-2015-9251"],
            "2.2.4": ["CVE-2015-9251", "CVE-2019-11358"],
        },
        "moment": {
            "2.29.1": ["CVE-2022-24785"],
            "2.24.0": ["CVE-2019-10744"],
        },
        "axios": {
            "0.21.1": ["CVE-2021-3749"],
            "0.19.0": ["CVE-2020-28168"],
        },
        "react": {
            "17.0.2": ["CVE-2021-32037"],
            "16.13.1": ["CVE-2020-15432"],
        },
        "react-dom": {
            "17.0.2": ["CVE-2021-32037"],
            "16.13.1": ["CVE-2020-15432"],
        },
        "express": {
            "4.17.1": ["CVE-2022-24999"],
            "4.16.4": ["CVE-2019-10742"],
        },
        "ws": {
            "7.4.6": ["CVE-2021-32640"],
            "6.2.1": ["CVE-2020-7662"],
        },
        "minimist": {
            "1.2.5": ["CVE-2021-44906"],
            "1.2.0": ["CVE-2020-7598"],
        },
        "yargs-parser": {
            "18.1.3": ["CVE-2021-37534"],
            "13.1.2": ["CVE-2020-7608"],
        },
        "node-forge": {
            "1.3.0": ["CVE-2022-0122"],
            "0.10.0": ["CVE-2019-10743"],
        },
    }

    async def run(self, recon: ReconData, http: HTTPClient) -> list[Finding]:
        findings = []
        all_content = recon.get_all_html() + "\n".join(await self._fetch_scripts(recon, http))
        deps = self._extract_dependencies(all_content)

        for name, version in deps:
            vulns = self._check_vulnerabilities(name, version)
            if vulns:
                findings.append(self._create_finding(name, version, vulns, recon))

        for f in findings:
            f.severity, f.score = calculate_severity(f.impact, f.likelihood)

        apply_tags_to_findings(findings, self.__class__.__name__)
        return findings

    async def _fetch_scripts(self, recon: ReconData, http: HTTPClient) -> list[str]:
        scripts = []
        for js_url in recon.get_js_bundles()[:10]:
            try:
                resp = await http.get(js_url)
                if resp.status_code == 200:
                    scripts.append(resp.text)
            except Exception:
                continue
        return scripts

    def _extract_dependencies(self, content: str) -> list[tuple[str, str]]:
        deps = []

        for pattern_name, pattern in VERSION_PATTERNS:
            for match in pattern.finditer(content):
                if pattern_name == "npm_package":
                    name, version = match.groups()
                    deps.append((name.lstrip("@"), version))
                elif pattern_name in ("import_map", "package_json"):
                    name, version = match.groups()
                    deps.append((name, version.lstrip("^~")))

        seen = set()
        unique = []
        for name, version in deps:
            key = (name.lower(), version)
            if key not in seen:
                seen.add(key)
                unique.append((name, version))

        return unique

    def _check_vulnerabilities(self, name: str, version: str) -> list[str]:
        name_lower = name.lower()
        if name_lower in self.KNOWN_VULNS:
            vuln_versions = self.KNOWN_VULNS[name_lower]
            for vuln_version, cves in vuln_versions.items():
                if self._version_matches_or_older(version, vuln_version):
                    return cves
        return []

    def _version_matches_or_older(self, current: str, vuln_version: str) -> bool:
        try:
            curr_parts = [int(x) for x in current.split(".")[:3]]
            vuln_parts = [int(x) for x in vuln_version.split(".")[:3]]
            return curr_parts <= vuln_parts
        except (ValueError, AttributeError):
            return False

    def _create_finding(self, name: str, version: str, cves: list[str], recon: ReconData) -> Finding:
        evidence = Evidence(
            url=recon.target_url,
            snippet=f"{name}@{version} has known vulnerabilities: {', '.join(cves)}",
            matched_pattern=f"{name}@{version}",
        )

        impact = 4
        likelihood = 3

        return Finding(
            check=self.name,
            title=f"Outdated Dependency: {name}@{version}",
            severity=SeverityLevel.HIGH,
            score=impact * likelihood,
            impact=impact,
            likelihood=likelihood,
            wstg_id="",
            attck_ids=[],
            evidence=evidence,
            confidence=0.7,
            remediation=(
                f"Update {name} to latest version: npm update {name} or yarn upgrade {name}. "
                f"Check changelog for breaking changes. "
                f"Run: npm audit fix"
            ),
            references=[f"https://github.com/advisories/{cve}" for cve in cves] + [
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Vulnerable_Components",
            ],
        )