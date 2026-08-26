from pathlib import Path

DEFAULT_KB_DIR = Path(__file__).parent / "knowledge_base"


def load_kb(kb_dir: Path | None = None) -> dict[str, str]:
    """Load all markdown files from the knowledge base directory.
    
    Returns a mapping of topic_name (filename without .md) -> content.
    """
    target_dir = kb_dir or DEFAULT_KB_DIR
    if not target_dir.exists():
        raise FileNotFoundError(f"Knowledge base directory not found: {target_dir}")

    kb: dict[str, str] = {}
    for md_file in sorted(target_dir.glob("*.md")):
        topic = md_file.stem
        kb[topic] = md_file.read_text(encoding="utf-8")
    return kb


def get_kb_topics(kb_dir: Path | None = None) -> list[str]:
    """Return list of available knowledge base topics."""
    return sorted(load_kb(kb_dir).keys())