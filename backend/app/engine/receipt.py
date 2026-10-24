"""Explainable Drift Receipt generation and Alert lifecycle per SPEC §9."""

import logging
from typing import Optional

from app.clock import Clock
from app.ids import new_id
from app.models import (
    Alert,
    Contract,
    Contribution,
    Decision,
    DriftReceipt,
    Event,
    RootCause,
    SessionState,
    Tier,
)
from app.store import Store

logger = logging.getLogger(__name__)

SHORT_REASONS: dict[str, str] = {
    "contract": "contract violation",
    "novelty": "novel tool use",
    "sequence": "unusual sequence",
    "taint_flow": "tainted data flow",
    "decoy": "decoy touched",
    "drift_cusum": "slow drift",
    "sigil": "missing/wrong sigil",
    "token_context": "token context change",
    "tool_integrity": "tool definition changed",
}


def build_drift_receipt(
    session: SessionState,
    contract: Optional[Contract],
    store: Store,
    clock: Clock,
) -> DriftReceipt:
    """Generate an explainable Drift Receipt for the session per SPEC §9."""
    events = store.list_events(session_id=session.session_id)
    alert_id = session.alert_id or new_id()
    timeline = [e.event_id for e in events]

    # 1. Identify first deviating event: risk >= 30 or any detector score >= 0.5
    first_deviating_event: Optional[Event] = None
    for ev in events:
        is_deviating = ev.risk >= 30 or any(d.score >= 0.5 for d in ev.detector_results)
        if is_deviating:
            first_deviating_event = ev
            break

    # 2. Determine root cause: most recent UNTRUSTED_IN before first deviating event
    root_cause: Optional[RootCause] = None
    dev_ts = first_deviating_event.timestamp if first_deviating_event else clock.now()

    eligible_refs = [ref for ref in session.taint_refs if ref.ts <= dev_ts]
    if eligible_refs:
        latest_ref = eligible_refs[-1]
        root_cause = RootCause(
            content_id=latest_ref.content_id,
            source=latest_ref.source,
            sha256=latest_ref.sha256,
            ts=latest_ref.ts,
            link_reason="Untrusted input read before behavioral deviation",
        )
    elif session.parent_session_id:
        # Check parent session for taint
        parent = store.get_session(session.parent_session_id)
        if parent and parent.taint_refs:
            parent_ref = parent.taint_refs[-1]
            root_cause = RootCause(
                content_id=f"parent:{parent_ref.content_id}",
                source=f"Delegated from parent session {parent.session_id} after reading {parent_ref.source}",
                sha256=parent_ref.sha256,
                ts=parent_ref.ts,
                link_reason="Taint inherited from parent session delegation instruction",
            )
        else:
            root_cause = RootCause(
                content_id=f"parent:{session.parent_session_id}",
                source=f"Delegated from parent session {session.parent_session_id}",
                sha256="",
                ts=session.created_at,
                link_reason="Taint and risk floor inherited via inter-agent delegation",
            )

    # 3. Contributions from highest-risk event; on a tie the LATEST wins (max() keeps the first it sees)
    highest_risk_event = max(reversed(events), key=lambda e: e.risk) if events else None
    contributions: list[Contribution] = []
    top_evidence = "Behavioral deviation detected"
    contract_clause = None

    if highest_risk_event:
        # Detector contributions
        for d in highest_risk_event.detector_results:
            if d.score > 0 and d.evidence:
                top_evidence = d.evidence[0]
                break

        # Re-derive contribution shares for highest-risk event if saved or fuse
        from app.engine.risk import fuse
        _, _, _, contribs = fuse(
            results=highest_risk_event.detector_results,
            sensitivity=highest_risk_event.sensitivity,
            session=session,
            event=highest_risk_event,
        )
        contributions = contribs
        if contribs:
            top_contrib = max(contribs, key=lambda c: c.share_pct)
            if top_contrib.evidence:
                top_evidence = top_contrib.evidence[0]

        # Identify violated contract clause
        for d in highest_risk_event.detector_results:
            if d.name == "contract" and d.score > 0:
                for ev_text in d.evidence:
                    if "data class" in ev_text.lower():
                        contract_clause = "allowed_data_classes"
                    elif "egress" in ev_text.lower():
                        contract_clause = "egress_allowlist"
                    elif "tool" in ev_text.lower():
                        contract_clause = "allowed_tools"
                    elif "delegate" in ev_text.lower():
                        contract_clause = "may_delegate_to"
                    elif "rate limit" in ev_text.lower():
                        contract_clause = "rate_limit_per_min"

    # 4. Headline template
    role = contract.role if contract else session.agent_id
    if root_cause and root_cause.source:
        headline = f"{role} · Risk {session.risk} · {top_evidence} · after reading {root_cause.source}"
    else:
        headline = f"{role} · Risk {session.risk} · {top_evidence} · no untrusted input — consider token theft"

    top_detector = max(contributions, key=lambda c: c.share_pct) if contributions else None
    if top_detector and top_detector.detector == "decoy" and "exfiltration" in " ".join(top_detector.evidence).lower():
        reason = "proven exfiltration"
    else:
        reason = SHORT_REASONS.get(top_detector.detector, "behaviour drift") if top_detector else "behaviour drift"
    via = f"via {root_cause.source.rstrip('/').rsplit('/', 1)[-1]}" if root_cause and root_cause.source else "no untrusted input"
    headline_short = f"{role} · Risk {session.risk} · {reason} · {via}"
    if len(headline_short) > 90:
        headline_short = headline_short[:89] + "…"

    # 5. Actions taken list
    actions_taken: list[str] = []
    if session.tier != Tier.ALLOW:
        actions_taken.append(f"Escalated session tier to {session.tier.value}")
    if session.decoy_mode:
        actions_taken.append("Session placed in decoy mode ('mirror world')")
    if session.removed_scopes:
        actions_taken.append(f"Scopes revoked via token shrink: {', '.join(session.removed_scopes)}")

    for ev in events:
        if ev.decision == Decision.hold:
            actions_taken.append(f"Held action '{ev.tool}' for human approval")
        elif ev.decision == Decision.sinkhole:
            actions_taken.append(f"Sinkholed '{ev.tool}' attempt to '{ev.target or 'destination'}'")
        elif ev.decision == Decision.decoy:
            actions_taken.append(f"Served mirror decoy content for '{ev.target}'")

    disabled_tools = store.list_disabled_tools()
    if disabled_tools:
        actions_taken.append(f"Disabled tools: {', '.join(disabled_tools)}")

    # 6. Tags collection
    tags_set: set[str] = set()
    for ev in events:
        for d in ev.detector_results:
            if d.score > 0:
                tags_set.update(d.tags)
    if session.parent_session_id or session.inherited_risk_floor > 0:
        tags_set.add("OWASP:ASI07")

    receipt = DriftReceipt(
        alert_id=alert_id,
        agent_id=session.agent_id,
        session_id=session.session_id,
        risk=session.risk,
        tier=session.tier,
        headline=headline,
        headline_short=headline_short,
        contributions=contributions,
        root_cause=root_cause,
        contract_clause=contract_clause,
        actions_taken=actions_taken,
        undo=f"POST /v1/sessions/{session.session_id}/restore",
        tags=sorted(list(tags_set)),
        timeline=timeline,
    )
    return receipt


def sync_session_alert(
    session: SessionState,
    contract: Optional[Contract],
    store: Store,
    clock: Clock,
) -> Optional[Alert]:
    """Create or update the session's Drift Alert and Receipt when tier >= WATCH."""
    if session.tier == Tier.ALLOW:
        return None

    receipt = build_drift_receipt(session, contract, store, clock)
    existing_alert = store.get_alert(receipt.alert_id) if session.alert_id else None

    if not existing_alert:
        # Search by session_id in store alerts
        # Alerts closed by a restore stay closed; a new drift opens a new alert
        session_alerts = [a for a in store.list_alerts(session_id=session.session_id) if a.status == "open"]
        if session_alerts:
            existing_alert = session_alerts[0]

    if existing_alert:
        existing_alert.risk = session.risk
        existing_alert.tier = session.tier
        existing_alert.headline = receipt.headline
        existing_alert.receipt = receipt
        store.save_alert(existing_alert)
        session.alert_id = existing_alert.alert_id
        return existing_alert
    else:
        new_alert = Alert(
            alert_id=receipt.alert_id,
            session_id=session.session_id,
            agent_id=session.agent_id,
            risk=session.risk,
            tier=session.tier,
            headline=receipt.headline,
            receipt=receipt,
            created_at=clock.now(),
            status="open",
        )
        session.alert_id = new_alert.alert_id
        store.save_alert(new_alert)
        return new_alert
