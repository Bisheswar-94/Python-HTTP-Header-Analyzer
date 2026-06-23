import unittest
from unittest.mock import MagicMock, patch

import requests

from header_analyzer import analyze_headers, main, normalize_url


class TestHeaderAnalyzer(unittest.TestCase):
    def test_missing_csp_header_results_in_high_risk(self):
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

    @patch("header_analyzer.print_report")
    @patch("header_analyzer.print_banner")
    @patch("header_analyzer.analyze_headers")
    @patch("header_analyzer.requests.Session")
    def test_main_uses_secure_request_options(
        self, session_cls, analyze_headers_mock, _print_banner_mock, _print_report_mock
    ):
        session = MagicMock()
        session_cls.return_value.__enter__.return_value = session
        session.get.return_value = MagicMock(headers={}, status_code=200)
        analyze_headers_mock.return_value = {
            "server": "Not disclosed",
            "content_type": "Unknown",
            "present_security_headers": [],
            "missing_security_headers": [],
            "risk_level": "Low",
        }

        with patch("sys.argv", ["header_analyzer.py", "example.com"]):
            exit_code = main()

        self.assertEqual(exit_code, 0)
        session.get.assert_called_once_with(
            "https://example.com", timeout=10, allow_redirects=True, verify=True
        )

    @patch("header_analyzer.print_banner")
    @patch("header_analyzer.requests.Session")
    def test_main_returns_error_on_request_exception(self, session_cls, _print_banner_mock):
        session = MagicMock()
        session_cls.return_value.__enter__.return_value = session
        session.get.side_effect = requests.RequestException("network failure")

        with patch("sys.argv", ["header_analyzer.py", "example.com"]):
            exit_code = main()

        self.assertEqual(exit_code, 1)


if __name__ == "__main__":
    unittest.main()
