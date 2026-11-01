import unittest

from core.detection_engine import Finding
from core.risk_scoring import calculate_risk


class TestRiskScoring(unittest.TestCase):

    def test_low_risk(self):
        result = calculate_risk([])

        self.assertEqual(result["score"], 0)
        self.assertEqual(result["risk_level"], "LOW")

    def test_medium_risk(self):
        findings = [
            Finding("URL001", "Test", "Test", "MEDIUM", 25)
        ]

        result = calculate_risk(findings)

        self.assertEqual(result["score"], 25)
        self.assertEqual(result["risk_level"], "MEDIUM")

    def test_high_risk(self):
        findings = [
            Finding("URL001", "Test", "Test", "HIGH", 45)
        ]

        result = calculate_risk(findings)

        self.assertEqual(result["score"], 45)
        self.assertEqual(result["risk_level"], "HIGH")

    def test_critical_risk(self):
        findings = [
            Finding("URL001", "Test", "Test", "HIGH", 75)
        ]

        result = calculate_risk(findings)

        self.assertEqual(result["score"], 75)
        self.assertEqual(result["risk_level"], "CRITICAL")

    def test_score_limit(self):
        findings = [
            Finding("URL001", "Test", "Test", "HIGH", 120)
        ]

        result = calculate_risk(findings)

        self.assertEqual(result["score"], 100)


if __name__ == "__main__":
    unittest.main()