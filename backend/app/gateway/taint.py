"""Taint tracking and label propagation per SPEC §5."""

import hashlib
import logging
from typing import Any
from app.clock import get_clock
from app.models import DATA_CLASS_SENSITIVITY, Effect, Sensitivity, SessionState, TaintLabel, TaintRef, Trust
from app.world.files import get_file
from app.world.tools import get_tool

logger = logging.getLogger(__name__)


def resolve_data_class_and_sensitivity(
    tool: str,
    args: dict[str, Any],
) -> tuple[str | None, Sensitivity | None]:
    """Resolve data_class and sensitivity from virtual file (for doc.read) or tool spec."""
    if tool == "doc.read":
        path = args.get("path", "")
        virtual_file = get_file(path)
        if virtual_file:
            data_class = virtual_file.data_class
            sensitivity = DATA_CLASS_SENSITIVITY.get(data_class, Sensitivity.internal)
            return data_class, sensitivity

    tool_spec = get_tool(tool)
    if tool_spec and tool_spec.data_class:
        data_class = tool_spec.data_class
        sensitivity = DATA_CLASS_SENSITIVITY.get(data_class, Sensitivity.internal)
        return data_class, sensitivity

    return None, None


def update_taint(
    session: SessionState,
    tool: str,
    args: dict[str, Any],
    result: Any,
) -> None:
    """Update session taint labels and references following tool execution per SPEC §5.

    - UNTRUSTED_IN (+ TaintRef) when untrusted content is read (doc.read, email.read).
    - SENSITIVE_READ when confidential or restricted data is read.
    EGRESS is set on attempt (held/sinkholed too) by mark_egress_attempt.
    """
    clock = get_clock()
    now_dt = clock.now()

    # 1. UNTRUSTED_IN check
    if tool == "doc.read":
        path = args.get("path", "")
        virtual_file = get_file(path)
        if virtual_file:
            if virtual_file.trust == Trust.untrusted:
                if TaintLabel.UNTRUSTED_IN not in session.taint_labels:
                    session.taint_labels.append(TaintLabel.UNTRUSTED_IN)

                content_str = virtual_file.content
                content_sha = hashlib.sha256(content_str.encode("utf-8")).hexdigest()
                ref = TaintRef(
                    content_id=virtual_file.path,
                    source=virtual_file.path,
                    sha256=content_sha,
                    ts=now_dt,
                )
                if not any(r.content_id == ref.content_id and r.sha256 == ref.sha256 for r in session.taint_refs):
                    session.taint_refs.append(ref)
                logger.info("Session %s tainted with UNTRUSTED_IN from %s", session.session_id, path)

    elif tool == "email.read":
        message_id = args.get("message_id", "")
        if TaintLabel.UNTRUSTED_IN not in session.taint_labels:
            session.taint_labels.append(TaintLabel.UNTRUSTED_IN)

        email_file = get_file(f"/inbox/{message_id}")
        content_str = email_file.content if email_file else str(result)
        content_sha = hashlib.sha256(content_str.encode("utf-8")).hexdigest()
        ref = TaintRef(
            content_id=message_id,
            source=f"/inbox/{message_id}",
            sha256=content_sha,
            ts=now_dt,
        )
        if not any(r.content_id == ref.content_id and r.sha256 == ref.sha256 for r in session.taint_refs):
            session.taint_refs.append(ref)
        logger.info("Session %s tainted with UNTRUSTED_IN from email %s", session.session_id, message_id)

    # 2. SENSITIVE_READ check
    # Reads only: payment.create (write, payments) must not count as a sensitive *read*
    tool_spec = get_tool(tool)
    data_class, sensitivity = resolve_data_class_and_sensitivity(tool, args)
    if tool_spec and tool_spec.effect == Effect.read and sensitivity in (Sensitivity.confidential, Sensitivity.restricted):
        if TaintLabel.SENSITIVE_READ not in session.taint_labels:
            session.taint_labels.append(TaintLabel.SENSITIVE_READ)
            logger.info("Session %s tainted with SENSITIVE_READ (class=%s)", session.session_id, data_class)


def mark_egress_attempt(session: SessionState, tool: str) -> None:
    """Set EGRESS when an egress tool is attempted, whatever the decision (SPEC §5)."""
    tool_spec = get_tool(tool)
    if tool_spec and tool_spec.effect == Effect.egress:
        if TaintLabel.EGRESS not in session.taint_labels:
            session.taint_labels.append(TaintLabel.EGRESS)
            logger.info("Session %s tainted with EGRESS by tool %s", session.session_id, tool)
