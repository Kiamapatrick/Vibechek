import logging

from vibeshield.models.report import JSONReport
from vibeshield.triage.baseline import baseline_triage
from vibeshield.triage.context.retriever import get_retriever
from vibeshield.triage.llm.client import get_client
from vibeshield.triage.models import TriageResult

log = logging.getLogger(__name__)


def run_triage(report: JSONReport) -> list[TriageResult]:
    """Run LLM triage on every finding in a scan report.

    A single finding failing (LLM error, malformed response, etc.) falls back
    to baseline for that finding — doesn't abort the whole batch.
    """
    if not report.findings:
        return []

    retriever = get_retriever()
    client = get_client()
    results: list[TriageResult] = []

    for finding in report.findings:
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