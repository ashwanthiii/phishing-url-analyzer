import csv
import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

import phishing_analyzer


class TestBatchCLI(unittest.TestCase):

    def test_batch_summary_skips_blank_rows_and_waits_between_vt_lookups(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "urls.csv")
            with open(path, "w", newline="", encoding="utf-8") as file:
                writer = csv.writer(file)
                writer.writerow(["url"])
                writer.writerow(["example.com"])
                writer.writerow(["example.net"])
                writer.writerow([""])
                writer.writerow(["bad url"])
                writer.writerow(["example.org"])
                writer.writerow(["example.edu"])

            levels = iter(["LOW", "MEDIUM", "INVALID", "HIGH", "CRITICAL"])

            def fake_analyze(url, use_vt=False, use_dns=False):
                level = next(levels)
                return {
                    "url": url,
                    "risk": {"risk_level": level},
                    "threat_intel": None if level == "INVALID" else {}
                }

            output = io.StringIO()
            with patch("sys.argv", [
                "phishing_analyzer.py", "--file", path, "--vt", "--dns",
                "--report"
            ]), patch.object(
                phishing_analyzer, "analyze_url", side_effect=fake_analyze
            ) as analyze_mock, patch.object(
                phishing_analyzer, "display_result"
            ), patch.object(
                phishing_analyzer.time, "sleep"
            ) as sleep, patch.object(
                phishing_analyzer, "export_report", return_value="report.csv"
            ) as export_report, redirect_stdout(output):
                phishing_analyzer.main()

            self.assertEqual(sleep.call_count, 3)
            self.assertTrue(all(call.args == (16,) for call in sleep.call_args_list))
            self.assertTrue(all(
                call.kwargs["use_dns"] for call in analyze_mock.call_args_list
            ))
            self.assertEqual(export_report.call_count, 5)
            self.assertIn("Total URLs: 5", output.getvalue())
            self.assertIn("LOW: 1", output.getvalue())
            self.assertIn("MEDIUM: 1", output.getvalue())
            self.assertIn("HIGH: 1", output.getvalue())
            self.assertIn("CRITICAL: 1", output.getvalue())
            self.assertIn("INVALID: 1", output.getvalue())
            self.assertEqual(
                output.getvalue().count(
                    "Waiting 16 seconds for VirusTotal rate limit..."
                ),
                3
            )


if __name__ == "__main__":
    unittest.main()
