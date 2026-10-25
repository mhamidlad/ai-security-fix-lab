"""Lab 2: Broken Access Control — Vulnerable implementation.

This code is intentionally vulnerable. Do not use in production.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Invoice:
    id: int
    user_id: int
    amount: float
    description: str


@dataclass
class User:
    id: int
    name: str
    email: str


# In-memory test data
INVOICES: dict[int, Invoice] = {
    1001: Invoice(id=1001, user_id=1, amount=500.00, description="Web hosting - Annual"),
    1002: Invoice(id=1002, user_id=1, amount=150.00, description="Domain renewal"),
    1003: Invoice(id=1003, user_id=2, amount=999.00, description="Enterprise license"),
    1004: Invoice(id=1004, user_id=2, amount=50.00, description="Support ticket"),
}

USERS: dict[int, User] = {
    1: User(id=1, name="Alice", email="alice@example.com"),
    2: User(id=2, name="Bob", email="bob@example.com"),
}


# ──────────────────────────────────────────────────────────────────────────
# VULNERABLE: No ownership check — any authenticated user can see any invoice
# ──────────────────────────────────────────────────────────────────────────

def get_invoice_vulnerable(invoice_id: int, authenticated_user_id: int) -> Optional[Invoice]:
    """VULNERABLE: Returns invoice by ID without checking ownership."""
    # VULNERABILITY: No check that the invoice belongs to authenticated_user_id
    return INVOICES.get(invoice_id)


# ──────────────────────────────────────────────────────────────────────────
# SECURE: Server-side authorization check
# ──────────────────────────────────────────────────────────────────────────

def get_invoice_secure(invoice_id: int, authenticated_user_id: int) -> Optional[Invoice]:
    """SECURE: Verifies the invoice belongs to the requesting user."""
    invoice = INVOICES.get(invoice_id)
    if invoice is None:
        return None
    
    # SECURE: Check that the invoice belongs to the authenticated user
    if invoice.user_id != authenticated_user_id:
        return None  # Authorization denied
    
    return invoice
