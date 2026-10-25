"""Tests for Lab 3: Cross-Site Scripting (XSS)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "labs" / "xss"))
from app_xss import (
    render_greeting_vulnerable,
    render_greeting_secure,
    render_comment_vulnerable,
    render_comment_secure,
)


class TestXSSVulnerable:

    def test_legitimate_name_renders(self):
        """Normal input renders correctly."""
        result = render_greeting_vulnerable("Alice")
        assert "Alice" in result
        assert "<h1>" in result

    def test_script_tag_not_escaped(self):
        """VULNERABILITY: Script tags are rendered without escaping."""
        result = render_greeting_vulnerable("<script>alert('XSS')</script>")
        # VULNERABILITY: The script tag is in the HTML unescaped
        assert "<script>" in result
        assert "alert" in result

    def test_event_handler_not_escaped(self):
        """VULNERABILITY: Event handler attributes pass through."""
        result = render_greeting_vulnerable("<img src=x onerror=alert(1)>")
        assert "onerror" in result
        assert "alert" in result

    def test_comment_allows_arbitrary_html(self):
        """VULNERABILITY: Comments allow arbitrary HTML."""
        result = render_comment_vulnerable("<script>steal(document.cookie)</script>")
        assert "<script>" in result


class TestXSSSecure:

    def test_legitimate_name_renders(self):
        """Normal input renders correctly."""
        result = render_greeting_secure("Alice")
        assert "Alice" in result
        assert "<h1>" in result

    def test_script_tag_escaped(self):
        """SECURE: Script tags are escaped."""
        result = render_greeting_secure("<script>alert('XSS')</script>")
        # SECURE: Script tags are HTML-escaped
        assert "<script>" not in result
        assert "&lt;script&gt;" in result

    def test_event_handler_escaped(self):
        """SECURE: Event handler attributes are escaped."""
        result = render_greeting_secure("<img src=x onerror=alert(1)>")
        assert "<img" not in result
        assert "&lt;img" in result

    def test_comment_escapes_html(self):
        """SECURE: Comments are HTML-escaped."""
        result = render_comment_secure("<script>steal(document.cookie)</script>")
        assert "<script>" not in result
        assert "&lt;script&gt;" in result

    def test_quotes_escaped(self):
        """SECURE: Single and double quotes are escaped."""
        result = render_greeting_secure("user' onclick='alert(1)")
        assert "'" not in result or "&#x27;" in result or "&quot;" in result
