"""Tests for Lab 5: Password Storage."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "labs" / "password-storage"))
from app_password_storage import (
    hash_password_vulnerable,
    verify_password_vulnerable,
    hash_password_secure,
    verify_password_secure,
)


class TestPasswordStorageVulnerable:

    def test_hash_and_verify_correct(self):
        """Legitimate password verification works."""
        h = hash_password_vulnerable("MyPassword123")
        assert verify_password_vulnerable("MyPassword123", h)

    def test_wrong_password_fails(self):
        """Incorrect password fails."""
        h = hash_password_vulnerable("MyPassword123")
        assert not verify_password_vulnerable("WrongPassword", h)

    def test_md5_is_deterministic(self):
        """VULNERABILITY: Same password always produces same hash (no salt)."""
        h1 = hash_password_vulnerable("MyPassword123")
        h2 = hash_password_vulnerable("MyPassword123")
        # VULNERABILITY: Identical hashes â€” no salt
        assert h1 == h2

    def test_md5_is_fast(self):
        """VULNERABILITY: MD5 is fast to compute â€” vulnerable to brute force."""
        import time
        start = time.time()
        for _ in range(1000):
            hash_password_vulnerable("test")
        elapsed = time.time() - start
        # MD5 is very fast â€” 1000 hashes should take < 0.1s
        assert elapsed < 0.1  # This is bad for password hashing

    def test_md5_collision_known(self):
        """VULNERABILITY: MD5 has known collision attacks."""
        # MD5 is cryptographically broken
        h = hash_password_vulnerable("test")
        assert len(h) == 32  # MD5 produces 32-char hex


class TestPasswordStorageSecure:

    def test_hash_and_verify_correct(self):
        """Legitimate password verification works."""
        h = hash_password_secure("MyPassword123")
        assert verify_password_secure("MyPassword123", h)

    def test_wrong_password_fails(self):
        """Incorrect password fails."""
        h = hash_password_secure("MyPassword123")
        assert not verify_password_secure("WrongPassword", h)

    def test_bcrypt_uses_salt(self):
        """SECURE: Same password produces different hashes (salt)."""
        h1 = hash_password_secure("MyPassword123")
        h2 = hash_password_secure("MyPassword123")
        # SECURE: Different hashes due to random salt
        assert h1 != h2

    def test_bcrypt_hash_format(self):
        """SECURE: bcrypt produces recognizable hash format."""
        h = hash_password_secure("test")
        assert h.startswith("$2b$")  # bcrypt format

    def test_bcrypt_work_factor(self):
        """SECURE: bcrypt uses configurable work factor."""
        h = hash_password_secure("test")
        # bcrypt $2b$XX$ where XX is the work factor
        parts = h.split("$")
        assert parts[2] == "12"  # work factor of 12

    def test_empty_password(self):
        """SECURE: Empty password still gets hashed (no plaintext)."""
        h = hash_password_secure("")
        assert verify_password_secure("", h)
        assert not verify_password_secure("x", h)
