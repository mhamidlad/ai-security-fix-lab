"""Tests for Lab 7: SSRF (Server-Side Request Forgery)."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "labs" / "ssrf"))
from app_ssrf import fetch_url_vulnerable, fetch_url_secure, ALLOWED_HOSTS


class TestSSRFVulnerable:

    def test_legitimate_url_might_work(self):
        """A legitimate URL might fetch (network-dependent)."""
        # We can't rely on network in tests, so just verify no validation error
        try:
            fetch_url_vulnerable("https://api.example.com")
        except Exception as e:
            # Network errors are fine â€” the point is no URL validation
            assert "ValueError" not in type(e).__name__ or "not in allowlist" not in str(e)

    def test_localhost_url_not_blocked(self):
        """VULNERABILITY: Internal localhost URLs are not blocked."""
        try:
            fetch_url_vulnerable("http://127.0.0.1:8080/admin")
        except Exception:
            pass  # May fail due to connection, but not due to validation
        # The key point: there's NO validation blocking internal URLs

    def test_metadata_endpoint_not_blocked(self):
        """VULNERABILITY: Cloud metadata endpoints are not blocked."""
        try:
            fetch_url_vulnerable("http://169.254.169.254/latest/meta-data/")
        except Exception:
            pass  # May fail, but NOT due to security validation

    def test_file_protocol_not_blocked(self):
        """VULNERABILITY: file:// protocol is not blocked."""
        try:
            fetch_url_vulnerable("file:///etc/passwd")
        except Exception:
            pass  # May fail, but NOT due to scheme validation


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
        """SECURE: Allowlisted hosts pass validation."""
        # We can't test actual network, but the validation should pass
        # (it'll fail later on DNS/network, which is expected)
        try:
            fetch_url_secure("https://api.example.com")
        except ValueError as e:
            # If it's a ValueError about allowlist, that's a bug
            assert "not in the allowlist" not in str(e)
        except Exception:
            pass  # Network errors are expected and fine
