"""Lab 8: Insecure Deserialization — Vulnerable implementation."""

import json
import pickle


# ──────────────────────────────────────────────────────────────────────────
# VULNERABLE: pickle.loads on untrusted data
# ──────────────────────────────────────────────────────────────────────────

class Session:
    def __init__(self, user_id: str, role: str = "user"):
        self.user_id = user_id
        self.role = role


def load_session_vulnerable(data: bytes) -> Session:
    """VULNERABLE: pickle can execute arbitrary code during deserialization."""
    # VULNERABILITY: pickle.loads can execute __reduce__ which runs arbitrary code
    # An attacker can craft a pickle payload that executes os.system("rm -rf /")
    obj = pickle.loads(data)
    return obj if isinstance(obj, Session) else Session("unknown")


# ──────────────────────────────────────────────────────────────────────────
# SECURE: JSON deserialization (no code execution)
# ──────────────────────────────────────────────────────────────────────────

def load_session_secure(data: str) -> Session:
    """SECURE: JSON.parse cannot execute arbitrary code."""
    obj = json.loads(data)
    user_id = obj.get("user_id", "unknown")
    role = obj.get("role", "user")
    return Session(user_id=user_id, role=role)


def save_session_secure(session: Session) -> str:
    """SECURE: Serialize session as JSON."""
    return json.dumps({"user_id": session.user_id, "role": session.role})
