"""JWT issuance, verification, and revocation for agent sessions."""

from datetime import timedelta
import logging
from typing import Any, Optional
import jwt

from app.clock import get_clock
from app.config import get_settings
from app.ids import new_id
from app.models import Contract, SessionState
from app.store import get_store
from app.world.tools import get_tool

logger = logging.getLogger(__name__)


def derive_scopes(contract: Contract) -> list[str]:
    """Derive token scopes from the set of effects of contract's allowed tools."""
    scopes: set[str] = set()
    for tool_name in contract.allowed_tools:
        tool_spec = get_tool(tool_name)
        if tool_spec and tool_spec.effect:
            scopes.add(tool_spec.effect.value)
    return sorted(list(scopes))


def issue(
    agent_id: str,
    session_id: str,
    scopes: list[str],
    act: Optional[list[str]] = None,
    jti: Optional[str] = None,
) -> str:
    """Issue a signed JWT token (HS256) valid for 15 minutes using the injectable clock."""
    settings = get_settings()
    clock = get_clock()
    now_dt = clock.now()

    token_jti = jti or new_id()
    iat = int(now_dt.timestamp())
    exp = int((now_dt + timedelta(minutes=15)).timestamp())

    payload: dict[str, Any] = {
        "sub": agent_id,
        "sid": session_id,
        "scopes": scopes,
        "jti": token_jti,
        "act": act or [],
        "iat": iat,
        "exp": exp,
    }

    token = jwt.encode(payload, settings.JWT_SECRET, algorithm="HS256")
    logger.debug("Issued JWT for agent=%s sid=%s jti=%s", agent_id, session_id, token_jti)
    return token


def verify(token: str) -> dict[str, Any]:
    """Verify JWT token: decode with HS256 only, enforce exp via injectable clock, check revocation."""
    settings = get_settings()
    clock = get_clock()
    store = get_store()

    # Decode signature with pinned algorithm
    try:
        claims = jwt.decode(
            token,
            settings.JWT_SECRET,
            algorithms=["HS256"],
            # exp/iat/nbf use wall-clock time in PyJWT; we enforce exp with the injectable clock below
            options={
                "verify_exp": False,
                "verify_iat": False,
                "verify_nbf": False,
                "require": ["exp", "jti", "sid", "sub", "scopes"],
            },
        )
    except jwt.PyJWTError as exc:
        logger.warning("JWT decode failed: %s", exc)
        raise ValueError(f"Invalid token: {exc}") from exc

    # Enforce expiry with injectable clock
    exp = claims["exp"]
    now_ts = int(clock.now().timestamp())
    if now_ts >= exp:
        logger.warning("Token expired: now=%d >= exp=%d", now_ts, exp)
        raise ValueError("Token has expired")

    # Check revoked JTIs
    jti = claims["jti"]
    if store.is_jti_revoked(jti):
        logger.warning("Token JTI is revoked: %s", jti)
        raise ValueError("Token JTI has been revoked")

    return claims


def revoke(jti: str) -> None:
    """Revoke a token by registering its JTI in the store."""
    store = get_store()
    store.revoke_jti(jti)
    logger.info("Revoked JTI: %s", jti)


def reissue(session: SessionState, scopes: list[str]) -> str:
    """Reissue a token with updated scopes, revoking the previous JTI."""
    if session.current_jti:
        revoke(session.current_jti)

    new_token_jti = new_id()
    new_token = issue(
        agent_id=session.agent_id,
        session_id=session.session_id,
        scopes=scopes,
        act=session.act,
        jti=new_token_jti,
    )

    session.token = new_token
    session.current_jti = new_token_jti
    session.updated_at = get_clock().now()

    store = get_store()
    store.save_session(session)
    logger.info("Reissued token for session=%s with new JTI=%s", session.session_id, new_token_jti)
    return new_token
