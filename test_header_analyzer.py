import unittest

from header_analyzer import analyze_headers, normalize_url


class TestHeaderAnalyzer(unittest.TestCase):
    def test_analyze_headers_identifies_missing_headers(self):
        headers = {
            "Server": "nginx",
            "Content-Type": "text/html",
            "X-Frame-Options": "DENY",
        }

        analysis = analyze_headers(headers)

        self.assertEqual(analysis["server"], "nginx")
        self.assertEqual(analysis["content_type"], "text/html")
        self.assertIn("X-Frame-Options", analysis["present_security_headers"])
        self.assertIn("Content-Security-Policy", analysis["missing_security_headers"])
        self.assertEqual(analysis["risk_level"], "High")

    def test_analyze_headers_all_present_is_low_risk(self):
        headers = {
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "Strict-Transport-Security": "max-age=63072000",
            "Permissions-Policy": "geolocation=()",
            "Referrer-Policy": "strict-origin-when-cross-origin",
        }

        analysis = analyze_headers(headers)

        self.assertEqual(analysis["missing_security_headers"], [])
        self.assertEqual(analysis["risk_level"], "Low")

    def test_analyze_headers_uses_defaults_when_headers_missing(self):
        analysis = analyze_headers({})

        self.assertEqual(analysis["server"], "Not disclosed")
        self.assertEqual(analysis["content_type"], "Unknown")

    def test_normalize_url_scheme_handling(self):
        self.assertEqual(normalize_url("example.com"), "https://example.com")
        self.assertEqual(normalize_url("https://example.com"), "https://example.com")
        self.assertEqual(normalize_url("http://example.com"), "http://example.com")


if __name__ == "__main__":
    unittest.main()
