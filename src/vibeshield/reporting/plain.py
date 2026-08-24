from vibeshield.models.report import PlainReport


class PlainReporter:
    @staticmethod
    def generate(report: PlainReport) -> str:
        return report.to_text()