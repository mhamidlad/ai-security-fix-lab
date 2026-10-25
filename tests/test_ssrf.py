"""Tests for Lab 7: SSRF (Server-Side Request Forgery)."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "labs" / "ssrf"))
from app_ssrf import fetch_url_secure, fetch_url_vulnerable


class TestSSRFVulnerable:

    def test_legitimate_url_might_work(self):
        """A legitimate URL fetches without validation error."""
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.read.return_value = b"Hello from API"
            mock_urlopen.return_value.__enter__.return_value = mock_resp
            result = fetch_url_vulnerable("https://api.example.com")
            assert result == "Hello from API"

    def test_localhost_url_not_blocked(self):
        """VULNERABILITY: Internal localhost URLs are not blocked."""
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.read.return_value = b"Admin console data"
            mock_urlopen.return_value.__enter__.return_value = mock_resp
            result = fetch_url_vulnerable("http://127.0.0.1:8080/admin")
            assert result == "Admin console data"
            mock_urlopen.assert_called_once_with("http://127.0.0.1:8080/admin")

    def test_metadata_endpoint_not_blocked(self):
        """VULNERABILITY: Cloud metadata endpoints are not blocked."""
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.read.return_value = b"ami-id\ninstance-id"
            mock_urlopen.return_value.__enter__.return_value = mock_resp
            result = fetch_url_vulnerable("http://169.254.169.254/latest/meta-data/")
            assert "ami-id" in result
            mock_urlopen.assert_called_once_with("http://169.254.169.254/latest/meta-data/")

    def test_file_protocol_not_blocked(self):
        """VULNERABILITY: file:// protocol is not blocked."""
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.read.return_value = b"root:x:0:0:root:/root:/bin/bash"
            mock_urlopen.return_value.__enter__.return_value = mock_resp
            result = fetch_url_vulnerable("file:///etc/passwd")
            assert "root:" in result
            mock_urlopen.assert_called_once_with("file:///etc/passwd")


class TestSSRFSecure:

    def test_non_allowlisted_host_blocked(self):
        """SECURE: Hosts not in allowlist are blocked."""
        with pytest.raises(ValueError, match="not in the allowlist"):
            fetch_url_secure("https://evil.example.com")

    def test_localhost_blocked(self):
        """SECURE: localhost is not in allowlist."""
        with pytest.raises(ValueError):
            fetch_url_secure("http://127.0.0.1:8080/admin")

    def test_metadata_endpoint_blocked(self):
        """SECURE: Cloud metadata endpoint is blocked."""
        with pytest.raises(ValueError):
            fetch_url_secure("http://169.254.169.254/latest/meta-data/")

    def test_file_protocol_blocked(self):
        """SECURE: file:// protocol is blocked."""
        with pytest.raises(ValueError, match="Only HTTP"):
            fetch_url_secure("file:///etc/passwd")

    def test_ftp_blocked(self):
        """SECURE: FTP is blocked."""
        with pytest.raises(ValueError, match="Only HTTP"):
            fetch_url_secure("ftp://example.com/file.txt")

    def test_allowlisted_host_accepted(self):
        """SECURE: Allowlisted hosts pass validation and fetch safely."""
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.read.return_value = b'{"status": "ok"}'
            mock_urlopen.return_value.__enter__.return_value = mock_resp
            result = fetch_url_secure("https://api.example.com")
            assert result == '{"status": "ok"}'
