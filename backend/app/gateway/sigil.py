"""Per-session Sigil generation and constant-time verification."""

import hmac
import secrets
from typing import Optional

from app.ids import is_seeded, new_id
from app.models import SessionState


def new_sigil() -> str:
    """Generate a new sigil canary formatted as 'SGL-' + 8 hex chars.

    Seeded deterministically when scenario seeding is active; otherwise cryptographically random.
    """
    if is_seeded():
        hex8 = new_id()[:8]
    else:
        hex8 = secrets.token_hex(4)
    return f"SGL-{hex8.upper()}"


def check(session: SessionState, presented: Optional[str]) -> str:
    """Verify presented sigil against session sigil using constant-time comparison.

    Returns:
        'valid' if matches,
        'missing' if not provided or empty,
        'wrong' if value does not match session secret.
    """
    if not presented or not presented.strip():
        return "missing"

    # Compare bytes: compare_digest raises TypeError on non-ASCII str (header values are latin-1).
    if hmac.compare_digest(session.sigil.strip().encode("utf-8"), presented.strip().encode("utf-8")):
        return "valid"
    return "wrong"
