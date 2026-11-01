import unittest

from core.url_parser import parse_url


class TestURLParser(unittest.TestCase):

    def test_valid_https_url(self):
        result = parse_url("https://example.com")

        self.assertTrue(result.is_valid)
        self.assertEqual(result.scheme, "https")
        self.assertEqual(result.hostname, "example.com")

    def test_url_without_scheme(self):
        result = parse_url("example.com")

        self.assertTrue(result.is_valid)
        self.assertEqual(result.scheme, "https")

    def test_ip_address(self):
        result = parse_url("http://192.0.2.10")

        self.assertTrue(result.is_valid)
        self.assertTrue(result.is_ip_address)

    def test_empty_url(self):
        result = parse_url("")

        self.assertFalse(result.is_valid)

    def test_invalid_scheme(self):
        result = parse_url("ftp://example.com")

        self.assertFalse(result.is_valid)

    def test_invalid_port(self):
        result = parse_url("https://example.com:99999")

        self.assertFalse(result.is_valid)


if __name__ == "__main__":
    unittest.main()