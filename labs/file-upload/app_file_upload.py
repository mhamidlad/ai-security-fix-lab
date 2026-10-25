"""Lab 4: Insecure File Upload — Vulnerable implementation."""

import os
import tempfile
from pathlib import Path


UPLOAD_DIR = Path(tempfile.gettempdir()) / "ai-fix-lab-uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


# ──────────────────────────────────────────────────────────────────────────
# VULNERABLE: No file type validation, uses original filename
# ──────────────────────────────────────────────────────────────────────────

def upload_file_vulnerable(filename: str, content: bytes) -> str:
    """VULNERABLE: Accepts any file type, uses original filename."""
    # VULNERABILITY 1: No file type validation
    # VULNERABILITY 2: Uses original filename (path traversal possible)
    # VULNERABILITY 3: No size limit
    dest = UPLOAD_DIR / filename
    dest.write_bytes(content)
    return str(dest)


# ──────────────────────────────────────────────────────────────────────────
# SECURE: File type allowlist, randomized names, size limit
# ──────────────────────────────────────────────────────────────────────────

import secrets

ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".pdf", ".txt", ".csv"}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB


def upload_file_secure(filename: str, content: bytes) -> str:
    """SECURE: Validates file type, uses random name, enforces size limit."""
    # Check file size
    if len(content) > MAX_FILE_SIZE:
        raise ValueError(f"File exceeds maximum size of {MAX_FILE_SIZE} bytes")
    
    # Validate file extension
    ext = Path(filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise ValueError(f"File type '{ext}' is not allowed")
    
    # Generate random filename to prevent path traversal and overwrites
    random_name = secrets.token_hex(16) + ext
    dest = UPLOAD_DIR / random_name
    
    # Write to safe path
    dest.write_bytes(content)
    return str(dest)
