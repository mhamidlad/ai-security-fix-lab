"""Lab 1: SQL Injection — Vulnerable implementation.

This code is intentionally vulnerable. Do not use in production.
"""

import sqlite3


def create_db():
    """Create a test database with sample users."""
    conn = sqlite3.connect(":memory:")
    conn.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        )
    """)
    conn.execute("INSERT INTO users (email, password, role) VALUES (?, ?, ?)", 
                 ("alice@example.com", "hashed_pw_1", "admin"))
    conn.execute("INSERT INTO users (email, password, role) VALUES (?, ?, ?)", 
                 ("bob@example.com", "hashed_pw_2", "user"))
    conn.commit()
    return conn


# ──────────────────────────────────────────────────────────────────────────
# VULNERABLE: String concatenation in SQL query
# ──────────────────────────────────────────────────────────────────────────

def login_vulnerable(email: str, password: str) -> dict | None:
    """Vulnerable login function — SQL injection via string concatenation."""
    conn = create_db()
    cursor = conn.cursor()
    
    # VULNERABILITY: User input concatenated directly into SQL
    query = "SELECT * FROM users WHERE email = '" + email + "' AND password = '" + password + "'"
    cursor.execute(query)
    
    row = cursor.fetchone()
    conn.close()
    
    if row:
        return {"id": row[0], "email": row[1], "role": row[3]}
    return None


# ──────────────────────────────────────────────────────────────────────────
# SECURE: Parameterized query with placeholders
# ──────────────────────────────────────────────────────────────────────────

def login_secure(email: str, password: str) -> dict | None:
    """Secure login function — parameterized query prevents injection."""
    conn = create_db()
    cursor = conn.cursor()
    
    # SECURE: Parameters passed separately, database handles escaping
    cursor.execute(
        "SELECT * FROM users WHERE email = ? AND password = ?",
        (email, password)
    )
    
    row = cursor.fetchone()
    conn.close()
    
    if row:
        return {"id": row[0], "email": row[1], "role": row[3]}
    return None
