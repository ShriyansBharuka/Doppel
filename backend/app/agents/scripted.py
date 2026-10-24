"""In-process scripted agent client per SPEC §10 / Prompt 4a Task 1."""

import logging
from typing import Any, Optional

from app.gateway.pipeline import handle_call
from app.gateway.sessions import start_session

logger = logging.getLogger(__name__)


class ScriptedAgent:
    """An agent that initiates a gateway session and executes tool calls in-process.

    Follows real gateway pipeline semantics (headers, sigil, runtime fingerprint)
    and automatically adopts new_token when returned.
    """

    def __init__(
        self,
        agent_id: str,
        runtime_fingerprint: Optional[str] = None,
        parent_session_id: Optional[str] = None,
    ) -> None:
        self.agent_id = agent_id
        self.runtime_fingerprint = runtime_fingerprint or f"fp-{agent_id}"
        self.parent_session_id = parent_session_id

        self.session_id: Optional[str] = None
        self.token: Optional[str] = None
        self.sigil: Optional[str] = None
        self.contract_version: Optional[int] = None

    def start(self) -> "ScriptedAgent":
        """Start the session through gateway sessions API and record initial credentials."""
        session, token, sigil = start_session(
            agent_id=self.agent_id,
            runtime_fingerprint=self.runtime_fingerprint,
            parent_session_id=self.parent_session_id,
        )
        self.session_id = session.session_id
        self.token = token
        self.sigil = sigil
        self.contract_version = session.contract_version
        logger.info(
            "ScriptedAgent '%s' started session %s (v%d)",
            self.agent_id,
            self.session_id,
            self.contract_version,
        )
        return self

    def call(
        self,
        tool: str,
        args: Optional[dict[str, Any]] = None,
        purpose: str = "",
        sigil: Optional[str] = None,
        runtime_fingerprint: Optional[str] = None,
        token: Optional[str] = None,
    ) -> dict[str, Any]:
        """Execute a tool call against the in-process gateway pipeline.

        Supports parameter overrides for testing attacker scenarios (e.g. stolen token, altered sigil).
        Automatically adopts new_token when issued.
        """
        if not self.session_id or not self.token:
            self.start()

        call_token = token if token is not None else (self.token or "")
        call_sigil = sigil if sigil is not None else self.sigil
        call_fp = runtime_fingerprint if runtime_fingerprint is not None else self.runtime_fingerprint
        call_args = args if args is not None else {}

        response = handle_call(
            session_id=self.session_id,  # type: ignore[arg-type]
            tool=tool,
            args=call_args,
            purpose=purpose,
            token=call_token,
            sigil=call_sigil,
            runtime_fingerprint=call_fp,
        )

        # Prompt 4a Task 1: automatically adopting new_token when returned
        returned_token = response.get("new_token")
        if returned_token:
            self.token = returned_token
            logger.info("ScriptedAgent '%s' adopted rotated token", self.agent_id)

        return response
