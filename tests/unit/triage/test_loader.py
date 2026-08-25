import tempfile
from pathlib import Path

import pytest

from vibeshield.triage.context.loader import get_kb_topics, load_kb

EXPECTED_TOPICS = {
    "cors",
    "debug_mode",
    "exposed_secrets",
    "outdated_deps",
    "patterns",
    "rate_limiting",
    "security_headers",
    "supabase_firebase",
    "unprotected_routes",
}


class TestLoadKB:
    def test_load_kb_returns_expected_topics(self):
        kb = load_kb()
        assert set(kb.keys()) == EXPECTED_TOPICS

    def test_load_kb_all_content_non_empty(self):
        kb = load_kb()
        for topic in EXPECTED_TOPICS:
            content = kb[topic]
            assert isinstance(content, str), f"Topic '{topic}' content is not a string"
            assert len(content) > 0, f"Topic '{topic}' content is empty"
            assert "WSTG / ATT&CK mapping" in content or topic == "patterns", (
                f"Topic '{topic}' missing WSTG/ATT&CK mapping section"
            )

    def test_load_kb_each_topic_has_substantive_content(self):
        kb = load_kb()
        for topic in EXPECTED_TOPICS:
            content = kb[topic]
            # Each topic should have meaningful content (at least a few paragraphs)
            lines = [line.strip() for line in content.split("\n") if line.strip()]
            assert len(lines) >= 10, f"Topic '{topic}' has too few content lines ({len(lines)})"

    def test_load_kb_nonexistent_directory_raises(self):
        with pytest.raises(FileNotFoundError):
            load_kb(Path("/nonexistent/directory/that/does/not/exist"))

    def test_load_kb_empty_directory_returns_empty_dict(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            kb = load_kb(Path(tmpdir))
            assert kb == {}

    def test_get_kb_topics_matches_load_kb_keys(self):
        topics = get_kb_topics()
        kb = load_kb()
        assert set(topics) == set(kb.keys())
        assert topics == sorted(topics)  # Should be sorted

    def test_get_kb_topics_empty_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            topics = get_kb_topics(Path(tmpdir))
            assert topics == []

    def test_get_kb_topics_nonexistent_directory_raises(self):
        with pytest.raises(FileNotFoundError):
            get_kb_topics(Path("/nonexistent/directory/that/does/not/exist"))