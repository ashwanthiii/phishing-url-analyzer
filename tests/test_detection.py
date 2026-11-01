import unittest

from core.url_parser import parse_url
from core.feature_extractor import extract_features
from core.detection_engine import detect_threats


class TestDetectionEngine(unittest.TestCase):

    def test_ip_address_detection(self):
        parsed = parse_url("http://192.0.2.10")

        features = extract_features(parsed)
        findings = detect_threats(features)

        detected_ids = [item.rule_id for item in findings]

        self.assertIn("URL002", detected_ids)

    def test_at_symbol_detection(self):
        parsed = parse_url(
            "https://example.com@evil.example/login"
        )

        features = extract_features(parsed)
        findings = detect_threats(features)

        detected_ids = [item.rule_id for item in findings]

        self.assertIn("URL001", detected_ids)

    def test_http_detection(self):
        parsed = parse_url("http://example.com")

        features = extract_features(parsed)
        findings = detect_threats(features)

        detected_ids = [item.rule_id for item in findings]

        self.assertIn("URL003", detected_ids)

    def test_punycode_detection(self):
        parsed = parse_url("https://xn--example-9d0b.com")

        features = extract_features(parsed)
        findings = detect_threats(features)

        detected_ids = [item.rule_id for item in findings]

        self.assertIn("URL004", detected_ids)

    def test_suspicious_keyword_in_domain(self):
        parsed = parse_url("https://login-example.com/")

        features = extract_features(parsed)
        findings = detect_threats(features)

        keyword_finding = next(
            item for item in findings if item.rule_id == "URL006"
        )
        self.assertEqual(features["keyword_locations"]["hostname"], ["login"])
        self.assertEqual(keyword_finding.points, 12)
        self.assertEqual(
            keyword_finding.description,
            "Suspicious keywords found in domain: login."
        )

    def test_suspicious_keyword_only_in_path(self):
        parsed = parse_url("https://example.com/account")

        features = extract_features(parsed)
        findings = detect_threats(features)

        keyword_finding = next(
            item for item in findings if item.rule_id == "URL006"
        )
        self.assertEqual(features["keyword_locations"]["hostname"], [])
        self.assertEqual(features["keyword_locations"]["path"], ["account"])
        self.assertEqual(keyword_finding.points, 5)
        self.assertEqual(
            keyword_finding.description,
            "Suspicious keywords found in path: account."
        )

    def test_no_suspicious_keyword(self):
        parsed = parse_url("https://example.com/about")

        features = extract_features(parsed)
        findings = detect_threats(features)

        self.assertFalse(features["contains_suspicious_keyword"])
        self.assertEqual(
            features["keyword_locations"],
            {"hostname": [], "path": [], "query": []}
        )
        self.assertNotIn("URL006", [item.rule_id for item in findings])


if __name__ == "__main__":
    unittest.main()