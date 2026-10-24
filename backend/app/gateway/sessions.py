"""Agent session lifecycle management and inheritance."""

import hashlib
import logging
from typing import Optional

from app.clock import get_clock
from app.gateway.sigil import new_sigil
from app.gateway.tokens import derive_scopes, issue
from app.ids import new_id
from app.models import SessionState, TaintLabel, TaintRef, Tier
from app.store import get_store

logger = logging.getLogger(__name__)


def start_session(
    agent_id: str,
    runtime_fingerprint: str,
    parent_session_id: Optional[str] = None,
) -> tuple[SessionState, str, str]:
    """Initialize an agent session, issue JWT token and intent canary sigil.

    If parent_session_id is provided, inherits parent's delegation chain and taint state per SPEC §5.
    """
    store = get_store()
    clock = get_clock()
    now_dt = clock.now()

    contract = store.get_contract(agent_id)
    if not contract:
        logger.error("Cannot start session: contract not found for agent_id=%s", agent_id)
        raise ValueError(f"No contract found for agent: {agent_id}")

    session_id = new_id()
    sigil = new_sigil()
    token_jti = new_id()

    act_chain: list[str] = []
    taint_labels: list[TaintLabel] = []
    taint_refs: list[TaintRef] = []
    inherited_risk_floor = 0

    if parent_session_id:
        parent_session = store.get_session(parent_session_id)
        if not parent_session:
            logger.warning("Parent session %s not found", parent_session_id)
            raise ValueError(f"Parent session not found: {parent_session_id}")

        # Delegation chain per SPEC §5: parent's act + parent agent_id
        act_chain = list(parent_session.act) + [parent_session.agent_id]
        # SPEC §7: snapshot now; the parent's risk keeps moving after delegation
        inherited_risk_floor = round(0.7 * parent_session.risk)

        # Inherit parent's taint labels and refs (SPEC §5)
        taint_labels = list(parent_session.taint_labels)
        taint_refs = list(parent_session.taint_refs)

        # SPEC §5: If parent is tainted with UNTRUSTED_IN, the delegated instruction itself counts as untrusted
        if TaintLabel.UNTRUSTED_IN in taint_labels:
            # Check if there is a queued delegation message for this target
            delegations = store.get_delegations(target_agent=agent_id)
            instruction_text = ""
            for d in reversed(delegations):
                if d.get("from_session") == parent_session_id:
                    instruction_text = d.get("instruction", "")
                    break

            if not instruction_text:
                instruction_text = f"delegated_instruction_from_{parent_session.agent_id}"

            parent_cause = parent_session.taint_refs[-1].source if parent_session.taint_refs else parent_session.agent_id
            if parent_cause.startswith("/inbox/"):
                cause_label = parent_cause[len("/inbox/"):]
            elif "/" in parent_cause:
                cause_label = parent_cause.split("/")[-1]
            else:
                cause_label = parent_cause

            instruction_hash = hashlib.sha256(instruction_text.encode("utf-8")).hexdigest()
            delegation_ref = TaintRef(
                content_id=f"delegation:{parent_session_id}",
                source=f"delegated instruction from {cause_label}",
                sha256=instruction_hash,
                ts=now_dt,
            )
            taint_refs.append(delegation_ref)

    # Scopes derived from contract's allowed tools' effects
    scopes = derive_scopes(contract)

    # Issue JWT token
    token = issue(
        agent_id=agent_id,
        session_id=session_id,
        scopes=scopes,
        act=act_chain,
        jti=token_jti,
    )

    session = SessionState(
        session_id=session_id,
        agent_id=agent_id,
        token=token,
        sigil=sigil,
        contract_version=contract.version,
        original_fingerprint=runtime_fingerprint,
        runtime_fingerprint=runtime_fingerprint,
        current_jti=token_jti,
        parent_session_id=parent_session_id,
        inherited_risk_floor=inherited_risk_floor,
        taint_labels=taint_labels,
        taint_refs=taint_refs,
        risk=0,
        tier=Tier.ALLOW,
        frozen=False,
        act=act_chain,
        created_at=now_dt,
        updated_at=now_dt,
        recent_call_timestamps=[],
    )

    store.save_session(session)
    logger.info(
        "Started session %s for agent %s (parent=%s, act=%s)",
        session_id,
        agent_id,
        parent_session_id,
        act_chain,
    )
    return session, token, sigil
