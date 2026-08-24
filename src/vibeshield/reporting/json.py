import json

from vibeshield.models.report import JSONReport


class JSONReporter:
    @staticmethod
    def generate(report: JSONReport, indent: int = 2) -> str:
        return json.dumps(report.to_dict(), indent=indent, ensure_ascii=False)

    @staticmethod
    def write_to_file(report: JSONReport, filepath: str, indent: int = 2) -> None:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report.to_dict(), f, indent=indent, ensure_ascii=False)