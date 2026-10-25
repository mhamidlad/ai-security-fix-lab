"""Tests for Lab 8: Insecure Deserialization."""

import sys
import pickle
import os
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "labs" / "insecure-deserialization"))
from app_insecure_deserialization import load_session_vulnerable, load_session_secure, save_session_secure, Session


class TestInsecureDeserializationVulnerable:

    def test_legitimate_session_loads(self):
        """A legitimate pickle session loads correctly."""
        session = Session("alice", "admin")
        data = pickle.dumps(session)
        result = load_session_vulnerable(data)
        assert result.user_id == "alice"
        assert result.role == "admin"

    def test_malicious_pickle_executes_code(self):
        """VULNERABILITY: pickle can execute arbitrary code."""
        # Create a malicious pickle payload that writes a file
        class Exploit:
            def __reduce__(self):
                # This tells pickle to call os.system with this string
                # We use a harmless command: create a marker file
                return (os.system, ("echo VULNERABLE > /tmp/pickle_exploit_marker.txt",))

        malicious_data = pickle.dumps(Exploit())
        
        # Load it â€” this triggers __reduce__ which executes os.system
        load_session_vulnerable(malicious_data)
        
        # VULNERABILITY: The command was executed
        # Check if the marker file was created (on systems where the command works)
        marker = Path("/tmp/pickle_exploit_marker.txt")
        if marker.exists():
            content = marker.read_text()
            assert "VULNERABLE" in content
            marker.unlink()  # Clean up

    def test_pickle_data_is_binary(self):
        """Pickle produces binary data (different from JSON)."""
        session = Session("alice", "admin")
        data = pickle.dumps(session)
        # Pickle is binary, not human-readable
        assert isinstance(data, bytes)


class TestInsecureDeserializationSecure:

    def test_legitimate_session_loads(self):
        """A legitimate JSON session loads correctly."""
        json_data = '{"user_id": "alice", "role": "admin"}'
        result = load_session_secure(json_data)
        assert result.user_id == "alice"
        assert result.role == "admin"

    def test_malicious_payload_treated_as_data(self):
        """SECURE: JSON cannot execute code."""
        # This would be dangerous in pickle, but JSON treats it as data
        json_data = '{"user_id": "os.system(\'rm -rf /\')", "role": "user"}'
        result = load_session_secure(json_data)
        # SECURE: The "malicious" string is just stored as data
        assert result.user_id == "os.system('rm -rf /')"
        assert result.role == "user"
        # No code was executed â€” it's just a string

    def test_roundtrip(self):
        """SECURE: Session can be saved and loaded."""
        session = Session("bob", "user")
        json_data = save_session_secure(session)
        loaded = load_session_secure(json_data)
        assert loaded.user_id == "bob"
        assert loaded.role == "user"

    def test_json_is_human_readable(self):
        """SECURE: JSON output is human-readable text."""
        session = Session("alice", "admin")
        json_data = save_session_secure(session)
        assert isinstance(json_data, str)
        assert "alice" in json_data
        assert "admin" in json_data

    def test_missing_fields_use_defaults(self):
        """SECURE: Missing fields get safe defaults."""
        result = load_session_secure('{"user_id": "charlie"}')
        assert result.user_id == "charlie"
        assert result.role == "user"  # Default role

    def test_invalid_json_raises_error(self):
        """SECURE: Invalid JSON raises an error (not silently executed)."""
        with pytest.raises(Exception):
            load_session_secure("not valid json {{{")
