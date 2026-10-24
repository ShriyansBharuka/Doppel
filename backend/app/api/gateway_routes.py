"""Agent-facing gateway API endpoints per SPEC §5."""

from typing import Any, Optional
from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, Field

from app.gateway.pipeline import handle_call
from app.gateway.sessions import start_session

router = APIRouter(prefix="/v1", tags=["gateway"])


class StartSessionRequest(BaseModel):
    """Payload to initiate an agent gateway session."""

    agent_id: str
    runtime_fingerprint: str = ""
    parent_session_id: Optional[str] = None


class StartSessionResponse(BaseModel):
    """Session initialization credentials and contract version."""

    session_id: str
    token: str
    sigil: str
    contract_version: int


class GatewayCallRequest(BaseModel):
    """Action payload for executing tools through the gateway."""

    session_id: str
    tool: str
    args: dict[str, Any] = Field(default_factory=dict)
    purpose: str = ""


@router.post("/sessions", response_model=StartSessionResponse)
def create_session(req: StartSessionRequest) -> StartSessionResponse:
    """Start an agent session, returning JWT token, intent canary sigil, and contract version."""
    try:
        session, token, sigil = start_session(
            agent_id=req.agent_id,
            runtime_fingerprint=req.runtime_fingerprint,
            parent_session_id=req.parent_session_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return StartSessionResponse(
        session_id=session.session_id,
        token=token,
        sigil=sigil,
        contract_version=session.contract_version,
    )


@router.post("/gateway/call")
def call_tool(
    req: GatewayCallRequest,
    authorization: Optional[str] = Header(None, alias="Authorization"),
    x_doppel_sigil: Optional[str] = Header(None, alias="X-Doppel-Sigil"),
    x_runtime_fingerprint: Optional[str] = Header(None, alias="X-Runtime-Fingerprint"),
) -> dict[str, Any]:
    """Execute a tool through the security gateway pipeline."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized: Missing Bearer token")

    token = authorization.split("Bearer ", 1)[1].strip()

    return handle_call(
        session_id=req.session_id,
        tool=req.tool,
        args=req.args,
        purpose=req.purpose,
        token=token,
        sigil=x_doppel_sigil,
        runtime_fingerprint=x_runtime_fingerprint,
    )
