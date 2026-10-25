"""Lab 6: Command Injection — Vulnerable implementation."""

import os
import subprocess
import shlex


# ──────────────────────────────────────────────────────────────────────────
# VULNERABLE: User input passed to shell
# ──────────────────────────────────────────────────────────────────────────

def ping_host_vulnerable(host: str) -> str:
    """VULNERABLE: User input in os.system with shell interpretation."""
    # VULNERABILITY: Shell metacharacters in host can execute arbitrary commands
    # Input: "example.com; rm -rf /" would execute both commands
    stream = os.popen(f"ping -c 1 {host}")
    return stream.read()


def run_command_vulnerable(command: str) -> str:
    """VULNERABLE: subprocess with shell=True and user input."""
    # VULNERABILITY: shell=True allows shell metacharacter injection.
    # The user input is interpolated directly into a shell command string,
    # so input such as "'; import os; os.system('whoami') #" would execute.
    import sys
    result = subprocess.run(
        f'"{sys.executable}" -c "print(\'{command}\')"',
        shell=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


# ──────────────────────────────────────────────────────────────────────────
# SECURE: No shell, argument array, input validation
# ──────────────────────────────────────────────────────────────────────────

ALLOWED_HOST_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-")


def ping_host_secure(host: str) -> str:
    """SECURE: Validates input, uses subprocess with argument list (no shell)."""
    # Validate hostname
    if not host or not all(c in ALLOWED_HOST_CHARS for c in host):
        raise ValueError("Invalid hostname")
    
    # SECURE: subprocess.run with list of arguments, no shell
    result = subprocess.run(
        ["ping", "-c", "1", host],
        capture_output=True,
        text=True,
        timeout=10,
    )
    return result.stdout


def run_command_secure(text: str) -> str:
    """SECURE: No shell execution, input treated as data not command."""
    # SECURE: Python invoked with an argument list, shell=False (default).
    # The input is passed as a positional argument — never interpreted
    # as a shell command, so metacharacters stay literal data.
    import sys
    result = subprocess.run(
        [sys.executable, "-c", "import sys; print(sys.argv[1])", text],
        capture_output=True,
        text=True,
        timeout=5,
    )
    return result.stdout
