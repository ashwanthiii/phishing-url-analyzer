import csv
import os
import tempfile
import unittest

from reports.report_generator import export_report


def sample_result(threat_intel=None):
    return {
        "url": "https://example.com",
        "hostname": "example.com",
        "valid": True,
        "findings": [],
        "risk": {
            "score": 0,
            "risk_level": "LOW",
            "total_findings": 0
        },
        "threat_intel": threat_intel
    }


class TestReportGenerator(unittest.TestCase):

    def test_writes_virustotal_fields_and_default_values(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "report.csv")
            export_report(sample_result(), path)

            with open(path, newline="", encoding="utf-8") as file:
                rows = list(csv.DictReader(file))

            self.assertEqual(rows[0]["vt_status"], "NOT_CHECKED")
            self.assertEqual(rows[0]["vt_detail"], "")

    def test_writes_virustotal_values(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "report.csv")
            export_report(
                sample_result({"status": "NO_KNOWN_THREAT", "detail": "Clean"}),
                path
            )

            with open(path, newline="", encoding="utf-8") as file:
                rows = list(csv.DictReader(file))

            self.assertEqual(rows[0]["vt_status"], "NO_KNOWN_THREAT")
            self.assertEqual(rows[0]["vt_detail"], "Clean")

    def test_does_not_add_header_to_existing_old_report(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "report.csv")
            old_header = "timestamp,url,hostname,valid,risk_score,risk_level,finding_count,findings\n"
            with open(path, "w", encoding="utf-8", newline="") as file:
                file.write(old_header)

            export_report(sample_result(), path)

            with open(path, encoding="utf-8") as file:
                lines = file.readlines()

            self.assertEqual(lines[0], old_header)
            self.assertEqual(len(lines), 2)


if __name__ == "__main__":
    unittest.main()
