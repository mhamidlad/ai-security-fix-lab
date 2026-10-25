# AI Security Fix Lab

[![CI](https://github.com/mhamidlad/ai-security-fix-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/mhamidlad/ai-security-fix-lab/actions/workflows/ci.yml)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security: OWASP Top 10](https://img.shields.io/badge/Security-OWASP%20Top%2010-red.svg)](https://owasp.org/www-project-top-ten/)
[![Tests: 74 Passing](https://img.shields.io/badge/tests-74%20passing-brightgreen.svg)](tests/)

> **Find the vulnerability. Reproduce it. Fix it. Prove the fix works.**

A collection of intentionally vulnerable code samples with complete remediation demonstrations. Each lab follows the same structure:

```
Vulnerable Code → Security Test → Root Cause → Secure Fix → Regression Test
```

## Why This Exists

Finding a vulnerability is only part of the job. If the development team cannot understand the issue, reproduce it, fix it, and prevent regression, the security work is incomplete.

This lab demonstrates that **I don't just find vulnerabilities — I fix them.**

## Labs

| # | Lab | Vulnerability | OWASP Category |
|---|-----|---------------|----------------|
| 1 | [SQL Injection](labs/sql-injection/) | String concatenation in queries | A03:2021 Injection |
| 2 | [Broken Access Control](labs/broken-access-control/) | Missing ownership checks | A01:2021 Broken Access Control |
| 3 | [Cross-Site Scripting](labs/xss/) | Unescaped user input | A03:2021 Injection (XSS) |
| 4 | [Insecure File Upload](labs/file-upload/) | No type/size validation | A04:2021 Insecure Design |
| 5 | [Password Storage](labs/password-storage/) | MD5 without salt | A02:2021 Cryptographic Failures |
| 6 | [Command Injection](labs/command-injection/) | Shell execution with user input | A03:2021 Injection |
| 7 | [SSRF](labs/ssrf/) | Unvalidated outbound requests | A10:2021 SSRF |
| 8 | [Insecure Deserialization](labs/insecure-deserialization/) | pickle.loads on untrusted data | A08:2021 Software & Data Integrity |

## How to Use

```bash
# Clone
git clone https://github.com/mhamidlad/ai-security-fix-lab.git
cd ai-security-fix-lab

# Install
pip install -e ".[dev]"

# Run all tests
python -m pytest -v

# Run a specific lab's tests
python -m pytest tests/test_sql_injection.py -v
```

Each lab directory contains:
- `app_*.py` — Both vulnerable and secure implementations side by side (one module per lab)
- Tests in `tests/test_*.py` — Demonstrating both the vulnerability and the fix

## Lab Structure

Each test file follows this pattern:

```python
class TestVulnerable:
    """Demonstrate that the vulnerable version is exploitable."""
    
    def test_legitimate_use_works(self):
        """Normal usage works correctly."""
        ...
    
    def test_attack_succeeds(self):
        """VULNERABILITY: The attack succeeds against vulnerable code."""
        ...

class TestSecure:
    """Demonstrate that the secure version is NOT exploitable."""
    
    def test_legitimate_use_works(self):
        """Normal usage still works correctly."""
        ...
    
    def test_attack_blocked(self):
        """SECURE: The attack is blocked by the fix."""
        ...
```

## Example: SQL Injection Lab

### Vulnerable Code
```python
query = "SELECT * FROM users WHERE email = '" + email + "'"
cursor.execute(query)
```

### Attack
```python
# SQL injection bypasses authentication
result = login_vulnerable("alice@example.com", "' OR '1'='1")
assert result is not None  # Injection succeeds!
```

### Secure Code
```python
cursor.execute(
    "SELECT * FROM users WHERE email = ? AND password = ?",
    (email, password)
)
```

### Regression Test
```python
# Same attack is blocked
result = login_secure("alice@example.com", "' OR '1'='1")
assert result is None  # SECURE: Injection blocked
```

## Technologies

`Python` `pytest` `bcrypt` `sqlite3` `subprocess` `urllib`

## License

MIT — See [LICENSE](LICENSE).

## Need Help Securing Your Application?

This project demonstrates practical approaches to identifying and mitigating
application security risks.

I also work on security reviews and remediation for real-world applications,
including AI-generated code, APIs, dependency risks, and CI/CD pipelines.

If your team needs help with:

- Reviewing AI-generated code for security vulnerabilities
- Investigating and fixing security findings
- Improving automated security testing
- Hardening GitHub Actions and deployment pipelines
- Assessing the security of AI-powered applications

You can reach me at **WhatsApp: +92 316 7417135** or open an issue.

For consulting inquiries, please include a short description of your
application, technology stack, and security objectives.

*Security testing is performed only on systems for which appropriate
authorization has been obtained.*

---

### Security First. Evidence Over Assumptions. Fixes Over Findings.

*All vulnerable code in this repository is intentionally insecure for
educational purposes. Do not use it in production.*
