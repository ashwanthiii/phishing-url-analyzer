import unittest

from core.typosquat import find_lookalike, registered_domain


class TestTyposquat(unittest.TestCase):

    def test_detects_missing_letter(self):
        result = find_lookalike("www.goole.com")
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "google.com")

    def test_exact_brand_not_flagged(self):
        self.assertIsNone(find_lookalike("www.google.com"))

    def test_subdomain_of_brand_not_flagged(self):
        self.assertIsNone(find_lookalike("mail.google.com"))

    def test_unrelated_domain_not_flagged(self):
        self.assertIsNone(find_lookalike("tawakkulboutique.in"))

    def test_registered_domain(self):
        self.assertEqual(registered_domain("a.b.example.com"), "example.com")


if __name__ == "__main__":
    unittest.main()