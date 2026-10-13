import logging

from vibeshield.models.finding import Finding
from vibeshield.triage.baseline import baseline_triage
from vibeshield.triage.context.retriever import BM25Retriever, get_retriever
from vibeshield.triage.llm.client import GroqClient, get_client
from vibeshield.triage.models import TriageResult

log = logging.getLogger(__name__)


def run_single_triage(
    finding: Finding,
    retriever: BM25Retriever,
    client: GroqClient,
) -> TriageResult:
    """Run LLM triage on a single finding with baseline fallback.

    This function can be called from async code via asyncio.to_thread
    to avoid blocking the event loop.
    """
    try:
        context = retriever.retrieve(finding)
        result = client.generate(finding, context)
        return result
    except Exception as e:
        log.warning(
            "LLM triage failed for finding %s (%s), falling back to baseline: %s",
            finding.id, finding.title, e,
            exc_info=True
        )
        # Fallback to baseline for this finding
        return baseline_triage(finding)


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
        result = run_single_triage(finding, retriever, client)
        results.append(result)

    return results