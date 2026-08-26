import tempfile
from pathlib import Path

from vibeshield.models.finding import Evidence, Finding, SeverityLevel
from vibeshield.triage.context.retriever import BM25Retriever, get_retriever


def _make_finding(
    check: str,
    title: str,
    snippet: str,
    wstg_id: str = "",
    attck_ids: list[str] | None = None,
) -> Finding:
    return Finding(
        check=check,
        title=title,
        severity=SeverityLevel.HIGH,
        score=16,
        impact=4,
        likelihood=4,
        wstg_id=wstg_id,
        attck_ids=attck_ids or [],
        evidence=Evidence(
            url="https://example.com/test",
            snippet=snippet,
        ),
        confidence=0.9,
        remediation="Test remediation",
        references=["https://example.com"],
    )


class TestBM25Retriever:
    def test_retrieve_supabase_finding_returns_supabase_doc(self):
        retriever = BM25Retriever()
        finding = _make_finding(
            check="supabase_firebase",
            title="RLS bypass on users table",
            snippet="GET /rest/v1/users returned data without authentication",
            wstg_id="WSTG-ATHZ-02",
            attck_ids=["T1213"],
        )
        results = retriever.retrieve(finding, k=3)
        assert len(results) > 0
        assert results[0].topic == "supabase_firebase"

    def test_retrieve_cors_finding_returns_cors_doc(self):
        retriever = BM25Retriever()
        finding = _make_finding(
            check="cors",
            title="Origin reflection with credentials",
            snippet="Access-Control-Allow-Origin: https://evil.com Access-Control-Allow-Credentials: true",
            wstg_id="WSTG-CONF-06",
            attck_ids=["T1190"],
        )
        results = retriever.retrieve(finding, k=3)
        assert len(results) > 0
        assert results[0].topic == "cors"

    def test_retrieve_rate_limiting_finding_returns_rate_limiting_doc(self):
        retriever = BM25Retriever()
        finding = _make_finding(
            check="rate_limiting",
            title="No rate limit on login endpoint",
            snippet="POST /api/auth/login 200 OK no 429 Retry-After header",
            wstg_id="WSTG-ATHN-01",
            attck_ids=["T1110.001", "T1110.003"],
        )
        results = retriever.retrieve(finding, k=3)
        assert len(results) > 0
        assert results[0].topic == "rate_limiting"

    def test_retrieve_respects_k_parameter(self):
        retriever = BM25Retriever()
        finding = _make_finding(
            check="supabase_firebase",
            title="RLS bypass",
            snippet="GET /rest/v1/users returned data",
            wstg_id="WSTG-ATHZ-02",
            attck_ids=["T1213"],
        )
        results_k1 = retriever.retrieve(finding, k=1)
        results_k5 = retriever.retrieve(finding, k=5)
        assert len(results_k1) == 1
        assert len(results_k5) <= 5

    def test_retrieve_returns_empty_list_for_no_overlap(self):
        retriever = BM25Retriever()
        finding = _make_finding(
            check="zzzqqqxxx",
            title="yyyppprrr",
            snippet="zzzqqqxxx",
            wstg_id="",
            attck_ids=[],
        )
        results = retriever.retrieve(finding, k=3)
        assert results == []

    def test_retrieve_results_ordered_by_relevance(self):
        retriever = BM25Retriever()
        finding = _make_finding(
            check="supabase_firebase",
            title="RLS bypass on users table",
            snippet="GET /rest/v1/users returned data without authentication RLS",
            wstg_id="WSTG-ATHZ-02",
            attck_ids=["T1213"],
        )
        results = retriever.retrieve(finding, k=3)
        assert len(results) >= 2
        query_tokens = retriever._tokenize(
            "supabase_firebase RLS bypass on users table GET /rest/v1/users returned data without authentication RLS WSTG-ATHZ-02 T1213"
        )
        scores = retriever._bm25.get_scores(query_tokens)
        for i in range(len(results) - 1):
            idx_i = next(j for j, d in enumerate(retriever._docs) if d.topic == results[i].topic)
            idx_j = next(j for j, d in enumerate(retriever._docs) if d.topic == results[i + 1].topic)
            assert scores[idx_i] >= scores[idx_j]


class TestGetRetriever:
    def test_get_retriever_default_is_singleton(self):
        r1 = get_retriever()
        r2 = get_retriever()
        assert r1 is r2

    def test_get_retriever_custom_dir_not_cached(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            kb_a = Path(tmpdir) / "a"
            kb_a.mkdir()
            (kb_a / "test.md").write_text("test content a")

            kb_b = Path(tmpdir) / "b"
            kb_b.mkdir()
            (kb_b / "test.md").write_text("test content b")

            r1 = get_retriever(kb_a)
            r2 = get_retriever(kb_b)
            r_default = get_retriever()

            assert r1 is not r2
            assert r1 is not r_default
            assert r2 is not r_default
            assert r1._docs[0].content == "test content a"
            assert r2._docs[0].content == "test content b"