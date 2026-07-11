import unittest
from unittest.mock import patch, MagicMock

from techdetect import run_techdetect, find_matches, CMS_SIGNATURES


class TestTechDetect(unittest.TestCase):

    def test_find_matches_detects_wordpress(self):
        page = "<html><link href='wp-content/theme.css'></html>"
        result = find_matches(page, CMS_SIGNATURES)
        self.assertIn("WordPress", result)

    def test_find_matches_returns_empty_when_no_match(self):
        page = "<html><body>plain site</body></html>"
        result = find_matches(page, CMS_SIGNATURES)
        self.assertEqual(result, [])

    @patch("techdetect.requests.get")
    def test_run_techdetect_handles_successful_response(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html>wp-content</html>"
        mock_response.headers = {"Server": "nginx"}
        mock_get.return_value = mock_response

        result = run_techdetect("example.com")

        self.assertEqual(result["status_code"], 200)
        self.assertEqual(result["server"], "nginx")
        self.assertIn("WordPress", result["cms"])
        self.assertIsNone(result["error"])

    @patch("techdetect.requests.get")
    def test_run_techdetect_handles_connection_error(self, mock_get):
        import requests
        mock_get.side_effect = requests.exceptions.ConnectionError("failed")

        result = run_techdetect("badtarget.invalid")

        self.assertIsNotNone(result["error"])
        self.assertEqual(result["status_code"], None)


if __name__ == "__main__":
    unittest.main()
