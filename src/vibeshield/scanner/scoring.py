from vibeshield.models.finding import Finding, SeverityLevel

IMPACT_DESCRIPTIONS = {
    1: "No direct data exposure",
    2: "PII or non-sensitive data exposure",
    3: "Authentication tokens or session data exposure",
    4: "Full database read access",
    5: "Full database write access or remote code execution",
}

LIKELIHOOD_DESCRIPTIONS = {
    1: "Theoretical - requires specific conditions",
    2: "Requires authenticated access",
    3: "Publicly accessible but complex exploitation",
    4: "Publicly accessible and trivial to exploit",
    5: "Automatable at scale with public tools",
}

SEVERITY_THRESHOLDS = {
    SeverityLevel.CRITICAL: (20, 25),
    SeverityLevel.HIGH: (12, 19),
    SeverityLevel.MEDIUM: (6, 11),
    SeverityLevel.LOW: (3, 5),
    SeverityLevel.INFO: (1, 2),
}


def calculate_severity(impact: int, likelihood: int) -> tuple[SeverityLevel, int]:
    if not (1 <= impact <= 5):
        raise ValueError(f"Impact must be 1-5, got {impact}")
    if not (1 <= likelihood <= 5):
        raise ValueError(f"Likelihood must be 1-5, got {likelihood}")

    score = impact * likelihood

    for severity, (min_score, max_score) in SEVERITY_THRESHOLDS.items():
        if min_score <= score <= max_score:
            return severity, score

    return SeverityLevel.INFO, score


def get_severity_consequence(severity: SeverityLevel) -> str:
    consequences = {
        SeverityLevel.CRITICAL: "Immediate action required - attacker can fully compromise your app and user data",
        SeverityLevel.HIGH: "Urgent fix needed - attacker can access sensitive data or bypass auth",
        SeverityLevel.MEDIUM: "Should fix soon - exposes information that aids attacks",
        SeverityLevel.LOW: "Fix when convenient - minor exposure or defense-in-depth gap",
        SeverityLevel.INFO: "Informational - no direct risk but worth knowing",
    }
    return consequences.get(severity, "")


def get_impact_description(impact: int) -> str:
    return IMPACT_DESCRIPTIONS.get(impact, "Unknown impact")


def get_likelihood_description(likelihood: int) -> str:
    return LIKELIHOOD_DESCRIPTIONS.get(likelihood, "Unknown likelihood")


def score_finding(finding: Finding) -> None:
    finding.severity, finding.score = calculate_severity(finding.impact, finding.likelihood)