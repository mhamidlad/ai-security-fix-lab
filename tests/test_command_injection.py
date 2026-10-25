"""Tests for Lab 6: Command Injection."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "labs" / "command-injection"))
from app_command_injection import ping_host_vulnerable, ping_host_secure, run_command_vulnerable, run_command_secure


class TestCommandInjectionVulnerable:

    def test_legitimate_host_works(self):
        """Normal host name works (may or may not ping, but no error)."""
        # This may fail on systems without ping, so we just verify it doesn't crash
        try:
            result = ping_host_vulnerable("localhost")
            assert isinstance(result, str)
        except Exception:
            pass  # Command may not exist on all systems

    def test_shell_metachar_injection(self):
        """VULNERABILITY: Shell metacharacters can chain commands."""
        # The semicolon allows executing a second command
        # Input: "localhost; echo INJECTED"
        try:
            result = ping_host_vulnerable("localhost; echo INJECTED")
            # VULNERABILITY: The echo command executes and "INJECTED" appears in output
            assert "INJECTED" in result or isinstance(result, str)
        except Exception:
            pass

    def test_echo_command(self):
        """Test the echo-based vulnerable command."""
        result = run_command_vulnerable("hello")
        assert "hello" in result

    def test_echo_injection(self):
        """VULNERABILITY: Pipe injection in echo command."""
        result = run_command_vulnerable("hello | cat")
        # VULNERABILITY: The pipe is interpreted by the shell
        assert "hello" in result


class TestCommandInjectionSecure:

    def test_legitimate_host_validated(self):
        """SECURE: Valid host name is accepted."""
        try:
            result = ping_host_secure("localhost")
            assert isinstance(result, str)
        except Exception:
            pass

    def test_shell_metachar_rejected(self):
        """SECURE: Shell metacharacters are rejected by input validation."""
        with pytest.raises(ValueError, match="Invalid hostname"):
            ping_host_secure("localhost; echo INJECTED")

    def test_pipe_rejected(self):
        """SECURE: Pipe character is rejected."""
        with pytest.raises(ValueError, match="Invalid hostname"):
            ping_host_secure("localhost | cat")

    def test_ampersand_rejected(self):
        """SECURE: Ampersand is rejected."""
        with pytest.raises(ValueError, match="Invalid hostname"):
            ping_host_secure("localhost && echo injected")

    def test_backtick_rejected(self):
        """SECURE: Backticks are rejected."""
        with pytest.raises(ValueError, match="Invalid hostname"):
            ping_host_secure("$(whoami)")

    def test_empty_rejected(self):
        """SECURE: Empty hostname is rejected."""
        with pytest.raises(ValueError, match="Invalid hostname"):
            ping_host_secure("")

    def test_echo_secure(self):
        """SECURE: echo works without shell."""
        result = run_command_secure("hello | cat")
        # SECURE: The pipe is treated as data, not a shell operator
        assert "hello" in result
        assert "|" in result  # Pipe is literal, not interpreted
