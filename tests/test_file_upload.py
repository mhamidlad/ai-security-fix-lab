"""Tests for Lab 4: Insecure File Upload."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "labs" / "file-upload"))
from app_file_upload import upload_file_vulnerable, upload_file_secure


class TestFileUploadVulnerable:

    def test_legitimate_file_uploads(self):
        """Normal file uploads successfully."""
        path = upload_file_vulnerable("photo.jpg", b"fake image data")
        assert Path(path).exists()

    def test_executable_uploads(self):
        """VULNERABILITY: No file type validation â€” .php files accepted."""
        path = upload_file_vulnerable("shell.php", b"<?php system($_GET['cmd']); ?>")
        # VULNERABILITY: PHP file is accepted
        assert Path(path).exists()

    def test_path_traversal(self):
        """VULNERABILITY: Original filename allows path traversal."""
        path = upload_file_vulnerable("../../malicious.py", b"evil code")
        # VULNERABILITY: Path traversal writes outside upload directory
        assert Path(path).exists()


class TestFileUploadSecure:

    def test_legitimate_file_uploads(self):
        """Normal file uploads successfully."""
        path = upload_file_secure("photo.jpg", b"fake image data")
        assert Path(path).exists()

    def test_executable_rejected(self):
        """SECURE: PHP files are rejected."""
        with pytest.raises(ValueError, match="not allowed"):
            upload_file_secure("shell.php", b"<?php system($_GET['cmd']); ?>")

    def test_path_traversal_blocked(self):
        """SECURE: Path traversal is blocked â€” random filename."""
        path = upload_file_secure("../../malicious.txt", b"evil code")
        # SECURE: The actual filename is randomized
        stored = Path(path)
        assert stored.exists()
        # The stored filename should NOT contain "malicious"
        assert "malicious" not in stored.name

    def test_large_file_rejected(self):
        """SECURE: Files over size limit are rejected."""
        large_content = b"x" * (11 * 1024 * 1024)  # 11MB
        with pytest.raises(ValueError, match="maximum size"):
            upload_file_secure("big.pdf", large_content)

    def test_random_filename(self):
        """SECURE: Files get randomized names."""
        path1 = upload_file_secure("test.txt", b"data1")
        path2 = upload_file_secure("test.txt", b"data2")
        # SECURE: Same input filename produces different stored filenames
        assert Path(path1).name != Path(path2).name
