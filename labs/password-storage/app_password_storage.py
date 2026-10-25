"""Lab 5: Password Storage — Vulnerable implementation."""

import hashlib
import os

import bcrypt


# ──────────────────────────────────────────────────────────────────────────
# VULNERABLE: MD5 hashing, no salt, plaintext comparison
# ──────────────────────────────────────────────────────────────────────────

def hash_password_vulnerable(password: str) -> str:
    """VULNERABLE: MD5 is broken and unsuitable for password hashing."""
    # VULNERABILITY: MD5 is cryptographically broken, no salt
    return hashlib.md5(password.encode()).hexdigest()


def verify_password_vulnerable(password: str, stored_hash: str) -> bool:
    """VULNERABLE: Compares hashes directly (timing attack possible)."""
    return hashlib.md5(password.encode()).hexdigest() == stored_hash


# ──────────────────────────────────────────────────────────────────────────
# SECURE: bcrypt with salt and work factor
# ──────────────────────────────────────────────────────────────────────────

def hash_password_secure(password: str) -> str:
    """SECURE: bcrypt with auto-generated salt and appropriate work factor."""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode(), salt).decode()


def verify_password_secure(password: str, stored_hash: str) -> bool:
    """SECURE: Uses bcrypt's constant-time comparison."""
    try:
        return bcrypt.checkpw(password.encode(), stored_hash.encode())
    except (ValueError, TypeError):
        return False
