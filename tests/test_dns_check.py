import io
import socket
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from core.dns_check import check_dns
import phishing_analyzer


class TestDNSCheck(unittest.TestCase):

    @patch("core.dns_check.socket.getaddrinfo")
    def test_resolves(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            ("family", "type", "protocol", "canonname", "address"),
            ("family", "type", "protocol", "canonname", "address")
        ]

        result = check_dns("example.com")

        self.assertEqual(result["source"], "DNS")
        self.assertEqual(result["status"], "RESOLVES")
        self.assertIn("2 address records", result["detail"])
        self.assertTrue(result["reason"])
        mock_getaddrinfo.assert_called_once_with("example.com", None)

    @patch("core.dns_check._internet_works", return_value=True)
    @patch("core.dns_check.socket.getaddrinfo")
    def test_does_not_resolve(self, mock_getaddrinfo, mock_internet_works):
        mock_getaddrinfo.side_effect = socket.gaierror(
            socket.EAI_NONAME, "Name or service not known"
        )

        result = check_dns("missing.example")

        self.assertEqual(result["status"], "DOES_NOT_RESOLVE")
        self.assertTrue(result["reason"])
        mock_internet_works.assert_called_once_with()

    @patch("core.dns_check._internet_works", return_value=False)
    @patch("core.dns_check.socket.getaddrinfo")
    def test_internet_down(self, mock_getaddrinfo, mock_internet_works):
        mock_getaddrinfo.side_effect = socket.gaierror(
            socket.EAI_NONAME, "Name or service not known"
        )

        result = check_dns("missing.example")

        self.assertEqual(result["status"], "UNABLE_TO_VERIFY")
        self.assertEqual(
            result["detail"],
            "Your internet or DNS seems unavailable."
        )
        self.assertTrue(result["reason"])
        mock_internet_works.assert_called_once_with()

    @patch("core.dns_check.socket.getaddrinfo")
    def test_ip_address_is_skipped(self, mock_getaddrinfo):
        result = check_dns("192.0.2.1")

        self.assertEqual(result["status"], "SKIPPED_IP")
        self.assertTrue(result["reason"])
        mock_getaddrinfo.assert_not_called()

    @patch("core.dns_check.socket.getaddrinfo")
    def test_empty_hostname(self, mock_getaddrinfo):
        result = check_dns("")

        self.assertEqual(result["status"], "UNABLE_TO_VERIFY")
        self.assertTrue(result["reason"])
        mock_getaddrinfo.assert_not_called()

    @patch("core.dns_check.socket.getaddrinfo")
    def test_temporary_dns_error_has_temporary_reason(self, mock_getaddrinfo):
        mock_getaddrinfo.side_effect = socket.gaierror(
            11002, "Temporary DNS failure"
        )

        result = check_dns("example.com")

        self.assertEqual(result["status"], "UNABLE_TO_VERIFY")
        self.assertIn("temporary error", result["reason"])

    @patch("phishing_analyzer.check_dns")
    def test_analyze_url_stores_dns_without_adding_finding_for_resolving_domain(
        self, mock_check_dns
    ):
        mock_check_dns.return_value = {
            "source": "DNS",
            "status": "RESOLVES",
            "detail": "Found 1 address records.",
            "reason": "The domain name exists and points to a server."
        }

        offline_result = phishing_analyzer.analyze_url("https://example.com")
        dns_result = phishing_analyzer.analyze_url(
            "https://example.com", use_dns=True
        )

        self.assertIsNone(offline_result["dns"])
        self.assertEqual(dns_result["dns"]["status"], "RESOLVES")
        self.assertEqual(dns_result["risk"]["score"], offline_result["risk"]["score"])
        self.assertNotIn(
            "DNS002",
            [finding["rule_id"] for finding in dns_result["findings"]]
        )
        mock_check_dns.assert_called_once_with("example.com")

    @patch("phishing_analyzer.check_dns")
    def test_does_not_resolve_adds_five_points(self, mock_check_dns):
        mock_check_dns.return_value = {
            "source": "DNS",
            "status": "DOES_NOT_RESOLVE",
            "detail": "Hostname was not found in DNS.",
            "reason": "The name has no active DNS records."
        }

        result = phishing_analyzer.analyze_url(
            "https://example.com", use_dns=True
        )

        dns_finding = next(
            finding for finding in result["findings"]
            if finding["rule_id"] == "DNS001"
        )
        self.assertEqual(dns_finding["points"], 5)
        self.assertEqual(result["risk"]["score"], 5)

    @patch("phishing_analyzer.check_dns")
    def test_resolving_lookalike_adds_fifteen_points(self, mock_check_dns):
        mock_check_dns.return_value = {
            "source": "DNS",
            "status": "RESOLVES",
            "detail": "Found 1 address records.",
            "reason": "The domain name exists and points to a server."
        }

        result = phishing_analyzer.analyze_url(
            "https://www.goole.com", use_dns=True
        )
        finding_ids = [finding["rule_id"] for finding in result["findings"]]

        dns_finding = next(
            finding for finding in result["findings"]
            if finding["rule_id"] == "DNS002"
        )
        self.assertIn("URL014", finding_ids)
        self.assertEqual(dns_finding["points"], 15)
        self.assertEqual(result["risk"]["score"], 45)

    @patch("phishing_analyzer.check_dns")
    def test_dns_disabled_adds_no_dns_finding(self, mock_check_dns):
        result = phishing_analyzer.analyze_url("https://www.goole.com")

        self.assertIsNone(result["dns"])
        self.assertEqual(result["risk"]["score"], 30)
        self.assertFalse(
            any(finding["rule_id"].startswith("DNS") for finding in result["findings"])
        )
        mock_check_dns.assert_not_called()

    @patch("phishing_analyzer.check_dns")
    def test_compact_output_explains_lookalike_and_temporary_dns(
        self, mock_check_dns
    ):
        mock_check_dns.return_value = {
            "source": "DNS",
            "status": "UNABLE_TO_VERIFY",
            "detail": "DNS lookup failed: Temporary DNS failure",
            "reason": (
                "Your network's DNS did not answer (temporary error). "
                "Try again or use another network."
            )
        }
        result = phishing_analyzer.analyze_url(
            "https://www.goole.com", use_dns=True
        )
        output = io.StringIO()

        with redirect_stdout(output):
            phishing_analyzer.display_result(result)

        displayed = output.getvalue()
        self.assertIn("Looks like google.com. This is NOT the official site.", displayed)
        self.assertIn("temporary error", displayed)

    @patch("phishing_analyzer.check_dns")
    def test_details_output_shows_reasons_for_both_checks(self, mock_check_dns):
        mock_check_dns.return_value = {
            "source": "DNS",
            "status": "RESOLVES",
            "detail": "Found 1 address records.",
            "reason": "DNS reason."
        }
        result = phishing_analyzer.analyze_url(
            "https://example.com", use_dns=True
        )
        result["threat_intel"] = {
            "source": "VirusTotal",
            "status": "NO_KNOWN_THREAT",
            "detail": "0 malicious, 0 suspicious vendor detections.",
            "reason": "VirusTotal reason."
        }
        output = io.StringIO()

        with redirect_stdout(output):
            phishing_analyzer.display_result(result, details=True)

        displayed = output.getvalue()
        self.assertIn("Reason: VirusTotal reason.", displayed)
        self.assertIn("Reason: DNS reason.", displayed)

    @patch("phishing_analyzer.check_dns")
    def test_invalid_url_keeps_dns_none(self, mock_check_dns):
        result = phishing_analyzer.analyze_url("bad url", use_dns=True)

        self.assertIsNone(result["dns"])
        mock_check_dns.assert_not_called()


if __name__ == "__main__":
    unittest.main()
