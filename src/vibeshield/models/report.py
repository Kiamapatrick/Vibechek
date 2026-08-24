from dataclasses import dataclass, field

from vibeshield.models.finding import Finding, SeverityLevel


@dataclass
class ScanMetadata:
    target: str
    timestamp: str
    version: str
    duration_ms: int
    crawl_depth: int
    max_pages: int
    pages_crawled: int
    checks_run: list[str]

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "timestamp": self.timestamp,
            "version": self.version,
            "duration_ms": self.duration_ms,
            "crawl_depth": self.crawl_depth,
            "max_pages": self.max_pages,
            "pages_crawled": self.pages_crawled,
            "checks_run": self.checks_run,
        }


@dataclass
class FingerprintResult:
    framework: str | None = None
    framework_version: str | None = None
    baas: list[str] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    headers: dict = field(default_factory=dict)
    js_bundles: list[str] = field(default_factory=list)
    api_endpoints: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "framework": self.framework,
            "framework_version": self.framework_version,
            "baas": self.baas,
            "technologies": self.technologies,
            "headers": self.headers,
            "js_bundles": self.js_bundles,
            "api_endpoints": self.api_endpoints,
        }


@dataclass
class Summary:
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0

    def to_dict(self) -> dict:
        return {
            "critical": self.critical,
            "high": self.high,
            "medium": self.medium,
            "low": self.low,
            "info": self.info,
        }

    @classmethod
    def from_findings(cls, findings: list[Finding]) -> "Summary":
        summary = cls()
        for f in findings:
            if f.severity == SeverityLevel.CRITICAL:
                summary.critical += 1
            elif f.severity == SeverityLevel.HIGH:
                summary.high += 1
            elif f.severity == SeverityLevel.MEDIUM:
                summary.medium += 1
            elif f.severity == SeverityLevel.LOW:
                summary.low += 1
            elif f.severity == SeverityLevel.INFO:
                summary.info += 1
        return summary


@dataclass
class JSONReport:
    scan_metadata: ScanMetadata
    fingerprint: FingerprintResult
    findings: list[Finding]
    summary: Summary

    def to_dict(self) -> dict:
        return {
            "scan_metadata": self.scan_metadata.to_dict(),
            "fingerprint": self.fingerprint.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "summary": self.summary.to_dict(),
        }


@dataclass
class PlainReport:
    scan_metadata: ScanMetadata
    fingerprint: FingerprintResult
    findings: list[Finding]
    summary: Summary

    def to_text(self) -> str:
        lines = []
        lines.append("=" * 60)
        lines.append("VibeShield Security Scan Report")
        lines.append("=" * 60)
        lines.append(f"Target: {self.scan_metadata.target}")
        lines.append(f"Scanned: {self.scan_metadata.timestamp}")
        lines.append(f"Duration: {self.scan_metadata.duration_ms}ms")
        lines.append(f"Pages crawled: {self.scan_metadata.pages_crawled}")
        lines.append("")
        
        if self.fingerprint.framework:
            lines.append(f"Framework: {self.fingerprint.framework}")
            if self.fingerprint.framework_version:
                lines.append(f"  Version: {self.fingerprint.framework_version}")
        if self.fingerprint.baas:
            lines.append(f"BaaS detected: {', '.join(self.fingerprint.baas)}")
        lines.append("")

        lines.append("-" * 60)
        lines.append(f"SUMMARY: {self.summary.critical} Critical, {self.summary.high} High, "
                     f"{self.summary.medium} Medium, {self.summary.low} Low, {self.summary.info} Info")
        lines.append("-" * 60)
        lines.append("")

        if not self.findings:
            lines.append("No issues found. Your app looks clean!")
            return "\n".join(lines)

        severity_order = [
            SeverityLevel.CRITICAL,
            SeverityLevel.HIGH,
            SeverityLevel.MEDIUM,
            SeverityLevel.LOW,
            SeverityLevel.INFO,
        ]

        for severity in severity_order:
            severity_findings = [f for f in self.findings if f.severity == severity]
            if not severity_findings:
                continue

            lines.append(f"\n### {severity.value} ({len(severity_findings)}) ###")
            lines.append("")

            for i, finding in enumerate(severity_findings, 1):
                lines.append(f"{i}. {finding.title}")
                lines.append(f"   What's wrong: {finding.remediation.split('.')[0]}.")
                lines.append(f"   Why it matters: {finding.references[0] if finding.references else 'See details in JSON report.'}")
                lines.append(f"   How to fix: {finding.remediation}")
                lines.append("")

        lines.append("=" * 60)
        lines.append("Full technical details available with --output json")
        lines.append("=" * 60)

        return "\n".join(lines)