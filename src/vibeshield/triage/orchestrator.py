import logging

from vibeshield.models.finding import Finding
from vibeshield.triage.baseline import baseline_triage
from vibeshield.triage.context.retriever import get_retriever
from vibeshield.triage.llm.client import get_client
from vibeshield.triage.models import TriageResult

log = logging.getLogger(__name__)


def run_triage(findings: list[Finding]) -> list[TriageResult]:
    """Run LLM triage on every finding.

    A single finding failing (LLM error, malformed response, etc.) falls back
    to baseline for that finding — doesn't abort the whole batch.
    """
    if not findings:
        return []

    retriever = get_retriever()
    try:
        client = get_client()
    except Exception as e:
        log.warning(
            "LLM client initialization failed, using baseline for all findings: %s",
            e,
            exc_info=True,
        )
        # No LLM available — fall back to baseline for all findings
        return [baseline_triage(f) for f in findings]

    results: list[TriageResult] = []

    for finding in findings:
        try:
            context = retriever.retrieve(finding)
            result = client.generate(finding, context)
            results.append(result)
        except Exception as e:
            log.warning(
                "LLM triage failed for finding %s (%s), falling back to baseline: %s",
                finding.id, finding.title, e,
                exc_info=True
            )
            # Fallback to baseline for this finding
            results.append(baseline_triage(finding))

    return results