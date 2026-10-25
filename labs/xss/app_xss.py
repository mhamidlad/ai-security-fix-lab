"""Lab 3: Cross-Site Scripting (XSS) — Vulnerable implementation."""

import html


# ──────────────────────────────────────────────────────────────────────────
# VULNERABLE: User input rendered without escaping
# ──────────────────────────────────────────────────────────────────────────

def render_greeting_vulnerable(name: str) -> str:
    """VULNERABLE: User input inserted directly into HTML."""
    # VULNERABILITY: No escaping of user input
    return f"<h1>Welcome, {name}</h1>"


def render_comment_vulnerable(comment: str) -> str:
    """VULNERABLE: User comment rendered as raw HTML."""
    # VULNERABILITY: User-controlled HTML is rendered directly
    return f'<div class="comment">{comment}</div>'


# ──────────────────────────────────────────────────────────────────────────
# SECURE: User input escaped before rendering
# ──────────────────────────────────────────────────────────────────────────

def render_greeting_secure(name: str) -> str:
    """SECURE: User input is HTML-escaped."""
    safe_name = html.escape(name)
    return f"<h1>Welcome, {safe_name}</h1>"


def render_comment_secure(comment: str) -> str:
    """SECURE: User input is HTML-escaped."""
    safe_comment = html.escape(comment)
    return f'<div class="comment">{safe_comment}</div>'
