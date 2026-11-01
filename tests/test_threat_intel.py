import io
import json
import os
import unittest
import urllib.error
from unittest.mock import patch, MagicMock

from core.threat_intel import check_virustotal


def fake_response(stats):
    body = json.dumps(
        {"data": {"attributes": {"last_analysis_stats": stats}}}
    ).encode()
    return io.BytesIO(body)


class TestThreatIntel(unittest.TestCase):

    def test_no_api_key(self):
        with patch.dict(os.environ, {}, clear=True):
            result = check_virustotal("https://example.com")
        self.assertEqual(result["status"], "UNABLE_TO_VERIFY")
        self.assertTrue(result["reason"])
        self.assertIn("No VT_API_KEY", result["reason"])

    @patch.dict(os.environ, {"VT_API_KEY": "dummy"})
    @patch("core.threat_intel.urllib.request.urlopen")
    def test_malicious(self, mock_open):
        mock_open.return_value.__enter__.return_value = fake_response(
            {"malicious": 5, "suspicious": 0}
        )
        result = check_virustotal("https://example.com")
        self.assertEqual(result["status"], "MALICIOUS")
        self.assertTrue(result["reason"])

    @patch.dict(os.environ, {"VT_API_KEY": "dummy"})
    @patch("core.threat_intel.urllib.request.urlopen")
    def test_suspicious(self, mock_open):
        mock_open.return_value.__enter__.return_value = fake_response(
            {"malicious": 1, "suspicious": 0}
        )
        result = check_virustotal("https://example.com")
        self.assertEqual(result["status"], "SUSPICIOUS")
        self.assertTrue(result["reason"])

    @patch.dict(os.environ, {"VT_API_KEY": "dummy"})
    @patch("core.threat_intel.urllib.request.urlopen")
    def test_clean(self, mock_open):
        mock_open.return_value.__enter__.return_value = fake_response(
            {"malicious": 0, "suspicious": 0}
        )
        result = check_virustotal("https://example.com")
        self.assertEqual(result["status"], "NO_KNOWN_THREAT")
        self.assertTrue(result["reason"])
        self.assertIn("does not mean it is safe", result["reason"])

    @patch.dict(os.environ, {"VT_API_KEY": "dummy"})
    @patch("core.threat_intel.urllib.request.urlopen")
    def test_not_in_database(self, mock_open):
        mock_open.side_effect = urllib.error.HTTPError(
            "url", 404, "Not Found", {}, None
        )
        result = check_virustotal("https://example.com")
        self.assertEqual(result["status"], "NOT_IN_DATABASE")
        self.assertTrue(result["reason"])

    @patch.dict(os.environ, {"VT_API_KEY": "dummy"})
    @patch("core.threat_intel.urllib.request.urlopen")
    def test_rate_limited(self, mock_open):
        mock_open.side_effect = urllib.error.HTTPError(
            "url", 429, "Too Many", {}, None
        )
        result = check_virustotal("https://example.com")
        self.assertEqual(result["status"], "UNABLE_TO_VERIFY")
        self.assertTrue(result["reason"])
        self.assertIn("free limit", result["reason"])


if __name__ == "__main__":
    unittest.main()