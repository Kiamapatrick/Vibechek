from dataclasses import dataclass
from pathlib import Path

from rank_bm25 import BM25Okapi

from vibeshield.models.finding import Finding
from vibeshield.triage.context.loader import load_kb
from vibeshield.triage.models import ContextSnippet


@dataclass
class _IndexedDoc:
    topic: str
    content: str
    tokens: list[str]


class BM25Retriever:
    """BM25-based retriever for knowledge base documents."""
    
    def __init__(self, kb_dir: Path | None = None) -> None:
        kb = load_kb(kb_dir)
        self._docs: list[_IndexedDoc] = []
        for topic, content in kb.items():
            tokens = self._tokenize(content)
            self._docs.append(_IndexedDoc(topic=topic, content=content, tokens=tokens))
        
        corpus = [doc.tokens for doc in self._docs]
        self._bm25 = BM25Okapi(corpus)
    
    @staticmethod
    def _tokenize(text: str) -> list[str]:
        """Simple whitespace + punctuation tokenization."""
        import re
        return re.findall(r"\b\w+\b", text.lower())
    
    def retrieve(self, finding: Finding, k: int = 3) -> list[ContextSnippet]:
        """Retrieve top-k relevant context snippets for a finding."""
        query = self._build_query(finding)
        query_tokens = self._tokenize(query)
        
        scores = self._bm25.get_scores(query_tokens)
        top_indices = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)[:k]
        
        results: list[ContextSnippet] = []
        for idx in top_indices:
            if scores[idx] > 0:
                doc = self._docs[idx]
                results.append(ContextSnippet(
                    topic=doc.topic,
                    content=doc.content,
                    source_file=f"{doc.topic}.md",
                ))
        return results
    
    def _build_query(self, finding: Finding) -> str:
        """Build search query from finding fields."""
        parts = [
            finding.check,
            finding.title,
            finding.evidence.snippet,
            " ".join(finding.attck_ids),
            finding.wstg_id,
        ]
        return " ".join(p for p in parts if p)


# Module-level singleton for reuse
_retriever: BM25Retriever | None = None


def get_retriever(kb_dir: Path | None = None) -> BM25Retriever:
    """Get or create the global BM25Retriever instance."""
    global _retriever
    if kb_dir is not None:
        return BM25Retriever(kb_dir)  # custom dir: never cache, always fresh
    if _retriever is None:
        _retriever = BM25Retriever()
    return _retriever