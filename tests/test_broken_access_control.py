"""Tests for Lab 2: Broken Access Control."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "labs" / "broken-access-control"))
from app_broken_access_control import get_invoice_vulnerable, get_invoice_secure


class TestBrokenAccessControlVulnerable:

    def test_owner_can_access_own_invoice(self):
        """User can access their own invoice."""
        result = get_invoice_vulnerable(1001, authenticated_user_id=1)
        assert result is not None
        assert result.id == 1001
        assert result.user_id == 1

    def test_user_can_access_other_users_invoice(self):
        """VULNERABILITY: Alice can access Bob's invoice."""
        # Alice (user_id=1) requests Bob's invoice (user_id=2, invoice_id=1003)
        result = get_invoice_vulnerable(1003, authenticated_user_id=1)
        # VULNERABILITY: Returns Bob's invoice to Alice!
        assert result is not None
        assert result.user_id == 2  # This is Bob's invoice

    def test_nonexistent_invoice_returns_none(self):
        """Nonexistent invoice returns None."""
        result = get_invoice_vulnerable(9999, authenticated_user_id=1)
        assert result is None


class TestBrokenAccessControlSecure:

    def test_owner_can_access_own_invoice(self):
        """User can access their own invoice."""
        result = get_invoice_secure(1001, authenticated_user_id=1)
        assert result is not None
        assert result.id == 1001
        assert result.user_id == 1

    def test_user_cannot_access_other_users_invoice(self):
        """SECURE: Alice cannot access Bob's invoice."""
        # Alice (user_id=1) requests Bob's invoice (user_id=2, invoice_id=1003)
        result = get_invoice_secure(1003, authenticated_user_id=1)
        # SECURE: Authorization denied â€” returns None
        assert result is None

    def test_nonexistent_invoice_returns_none(self):
        """Nonexistent invoice returns None."""
        result = get_invoice_secure(9999, authenticated_user_id=1)
        assert result is None

    def test_bob_can_access_own_invoice(self):
        """Bob can access his own invoices."""
        result = get_invoice_secure(1003, authenticated_user_id=2)
        assert result is not None
        assert result.user_id == 2
