"""Tests for Lab 1: SQL Injection.

These tests demonstrate:
1. The vulnerability exists (SQL injection attack succeeds)
2. The secure version is not vulnerable
3. The secure version still works correctly for legitimate users
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "labs" / "sql-injection"))
from app_sql_injection import login_vulnerable, login_secure


class TestSQLInjectionVulnerable:
    """Demonstrate that the vulnerable version is exploitable."""

    def test_legitimate_login_succeeds(self):
        """A legitimate user can log in with correct credentials."""
        result = login_vulnerable("alice@example.com", "hashed_pw_1")
        assert result is not None
        assert result["email"] == "alice@example.com"
        assert result["role"] == "admin"

    def test_wrong_password_fails(self):
        """Incorrect password should fail."""
        result = login_vulnerable("alice@example.com", "wrong_password")
        assert result is None

    def test_sql_injection_bypasses_auth(self):
        """SQL injection bypasses authentication entirely."""
        # Classic SQL injection: ' OR '1'='1
        # This makes the WHERE clause always true
        result = login_vulnerable("alice@example.com", "' OR '1'='1")
        assert result is not None  # VULNERABILITY: Injection succeeds!
        assert result["email"] == "alice@example.com"

    def test_sql_injection_returns_all_users(self):
        """SQL injection can return any user's data."""
        # UNION-based injection
        result = login_vulnerable("' UNION SELECT 1, 'admin@evil.com', 'x', 'admin' -- ", "x")
        # The injection succeeds â€” the query returns data
        assert result is not None  # VULNERABILITY


class TestSQLInjectionSecure:
    """Demonstrate that the secure version is NOT exploitable."""

    def test_legitimate_login_succeeds(self):
        """A legitimate user can log in with correct credentials."""
        result = login_secure("alice@example.com", "hashed_pw_1")
        assert result is not None
        assert result["email"] == "alice@example.com"
        assert result["role"] == "admin"

    def test_wrong_password_fails(self):
        """Incorrect password should fail."""
        result = login_secure("alice@example.com", "wrong_password")
        assert result is None

    def test_sql_injection_blocked(self):
        """SQL injection attack is blocked by parameterized query."""
        # The same injection that worked on the vulnerable version
        result = login_secure("alice@example.com", "' OR '1'='1")
        # SECURE: Injection treated as literal string, no match found
        assert result is None

    def test_union_injection_blocked(self):
        """UNION-based injection is blocked."""
        result = login_secure("' UNION SELECT 1, 'admin@evil.com', 'x', 'admin' -- ", "x")
        assert result is None

    def test_comment_injection_blocked(self):
        """Comment-based injection is blocked."""
        result = login_secure("alice@example.com' -- ", "anything")
        assert result is None
