import json
from pathlib import Path
from typing import Any

from vibeshield.models.finding import Finding


def load_report(path: Path) -> list[Finding]:
    with path.open("r", encoding="utf-8") as f:
        data: dict[str, Any] = json.load(f)

    findings_data = data.get("findings", [])
    return [Finding.from_dict(fd) for fd in findings_data]