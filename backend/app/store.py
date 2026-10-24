"""Storage interface and in-memory implementation."""

from typing import Any, Optional, Protocol, runtime_checkable
from app.config import get_settings
from app.models import (
    Alert,
    Approval,
    Contract,
    Event,
    SessionState,
    SinkholeCapture,
)


@runtime_checkable
class Store(Protocol):
    """Storage protocol for Doppel domain state."""

    # Contracts
    def save_contract(self, contract: Contract) -> None: ...
    def get_contract(self, agent_id: str) -> Optional[Contract]: ...
    def list_contracts(self) -> list[Contract]: ...

    # Sessions
    def save_session(self, session: SessionState) -> None: ...
    def get_session(self, session_id: str) -> Optional[SessionState]: ...
    def list_sessions(self) -> list[SessionState]: ...

    # Events
    def save_event(self, event: Event) -> None: ...
    def get_event(self, event_id: str) -> Optional[Event]: ...
    def list_events(self, session_id: Optional[str] = None) -> list[Event]: ...

    # Alerts
    def save_alert(self, alert: Alert) -> None: ...
    def get_alert(self, alert_id: str) -> Optional[Alert]: ...
    def list_alerts(self, session_id: Optional[str] = None) -> list[Alert]: ...

    # Sinkhole captures
    def save_sinkhole_capture(self, capture: SinkholeCapture) -> None: ...
    def list_sinkhole_captures(self) -> list[SinkholeCapture]: ...

    # Approvals
    def save_approval(self, approval: Approval) -> None: ...
    def get_approval(self, approval_id: str) -> Optional[Approval]: ...
    def list_approvals(self, session_id: Optional[str] = None) -> list[Approval]: ...

    # Revoked JTIs
    def revoke_jti(self, jti: str) -> None: ...
    def is_jti_revoked(self, jti: str) -> bool: ...

    # Disabled tools
    def disable_tool(self, tool_name: str) -> None: ...
    def enable_tool(self, tool_name: str) -> None: ...
    def is_tool_disabled(self, tool_name: str) -> bool: ...
    def list_disabled_tools(self) -> list[str]: ...

    # Pinned tool hashes
    def pin_tool_hash(self, tool_name: str, schema_hash: str) -> None: ...
    def get_pinned_tool_hash(self, tool_name: str) -> Optional[str]: ...
    def get_all_pinned_tool_hashes(self) -> dict[str, str]: ...

    # Delegations
    def queue_delegation(self, msg: dict[str, Any]) -> None: ...
    def get_delegations(self, target_agent: Optional[str] = None) -> list[dict[str, Any]]: ...

    # Egress logs
    def record_egress(self, entry: dict[str, Any]) -> None: ...
    def get_egress_logs(self) -> list[dict[str, Any]]: ...

    # Reset
    def reset(self) -> None: ...


class InMemoryStore:
    """Thread-safe, in-memory reference store implementation."""

    def __init__(self) -> None:
        self._contracts: dict[str, Contract] = {}
        self._sessions: dict[str, SessionState] = {}
        self._events: dict[str, Event] = {}
        self._alerts: dict[str, Alert] = {}
        self._sinkhole_captures: list[SinkholeCapture] = []
        self._approvals: dict[str, Approval] = {}
        self._revoked_jtis: set[str] = set()
        self._disabled_tools: set[str] = set()
        self._pinned_tool_hashes: dict[str, str] = {}
        self._delegations: list[dict[str, Any]] = []
        self._egress_logs: list[dict[str, Any]] = []

    # Contracts
    def save_contract(self, contract: Contract) -> None:
        self._contracts[contract.agent_id] = contract

    def get_contract(self, agent_id: str) -> Optional[Contract]:
        return self._contracts.get(agent_id)

    def list_contracts(self) -> list[Contract]:
        return list(self._contracts.values())

    # Sessions
    def save_session(self, session: SessionState) -> None:
        self._sessions[session.session_id] = session

    def get_session(self, session_id: str) -> Optional[SessionState]:
        return self._sessions.get(session_id)

    def list_sessions(self) -> list[SessionState]:
        return list(self._sessions.values())

    # Events
    def save_event(self, event: Event) -> None:
        self._events[event.event_id] = event

    def get_event(self, event_id: str) -> Optional[Event]:
        return self._events.get(event_id)

    def list_events(self, session_id: Optional[str] = None) -> list[Event]:
        if session_id:
            return [e for e in self._events.values() if e.session_id == session_id]
        return list(self._events.values())

    # Alerts
    def save_alert(self, alert: Alert) -> None:
        self._alerts[alert.alert_id] = alert

    def get_alert(self, alert_id: str) -> Optional[Alert]:
        return self._alerts.get(alert_id)

    def list_alerts(self, session_id: Optional[str] = None) -> list[Alert]:
        if session_id:
            return [a for a in self._alerts.values() if a.session_id == session_id]
        return list(self._alerts.values())

    # Sinkhole captures
    def save_sinkhole_capture(self, capture: SinkholeCapture) -> None:
        self._sinkhole_captures.append(capture)

    def list_sinkhole_captures(self) -> list[SinkholeCapture]:
        return list(self._sinkhole_captures)

    # Approvals
    def save_approval(self, approval: Approval) -> None:
        self._approvals[approval.approval_id] = approval

    def get_approval(self, approval_id: str) -> Optional[Approval]:
        return self._approvals.get(approval_id)

    def list_approvals(self, session_id: Optional[str] = None) -> list[Approval]:
        if session_id:
            return [a for a in self._approvals.values() if a.session_id == session_id]
        return list(self._approvals.values())

    # Revoked JTIs
    def revoke_jti(self, jti: str) -> None:
        self._revoked_jtis.add(jti)

    def is_jti_revoked(self, jti: str) -> bool:
        return jti in self._revoked_jtis

    # Disabled tools
    def disable_tool(self, tool_name: str) -> None:
        self._disabled_tools.add(tool_name)

    def enable_tool(self, tool_name: str) -> None:
        self._disabled_tools.discard(tool_name)

    def is_tool_disabled(self, tool_name: str) -> bool:
        return tool_name in self._disabled_tools

    def list_disabled_tools(self) -> list[str]:
        return sorted(list(self._disabled_tools))

    # Pinned tool hashes
    def pin_tool_hash(self, tool_name: str, schema_hash: str) -> None:
        self._pinned_tool_hashes[tool_name] = schema_hash

    def get_pinned_tool_hash(self, tool_name: str) -> Optional[str]:
        return self._pinned_tool_hashes.get(tool_name)

    def get_all_pinned_tool_hashes(self) -> dict[str, str]:
        return dict(self._pinned_tool_hashes)

    # Delegations
    def queue_delegation(self, msg: dict[str, Any]) -> None:
        self._delegations.append(msg)

    def get_delegations(self, target_agent: Optional[str] = None) -> list[dict[str, Any]]:
        if target_agent:
            return [d for d in self._delegations if d.get("to_agent") == target_agent]
        return list(self._delegations)

    # Egress logs
    def record_egress(self, entry: dict[str, Any]) -> None:
        self._egress_logs.append(entry)

    def get_egress_logs(self) -> list[dict[str, Any]]:
        return list(self._egress_logs)

    # Reset
    def reset(self) -> None:
        """Reset all in-memory collections to empty states."""
        self._contracts.clear()
        self._sessions.clear()
        self._events.clear()
        self._alerts.clear()
        self._sinkhole_captures.clear()
        self._approvals.clear()
        self._revoked_jtis.clear()
        self._disabled_tools.clear()
        self._pinned_tool_hashes.clear()
        self._delegations.clear()
        self._egress_logs.clear()


_global_in_memory_store = InMemoryStore()


def get_store() -> Store:
    """Return configured Store singleton.

    Raises:
        NotImplementedError: If STORAGE is set to 'mongo'.
        ValueError: If STORAGE backend is unknown.
    """
    settings = get_settings()
    storage_type = settings.STORAGE.lower()

    if storage_type == "memory":
        return _global_in_memory_store
    elif storage_type == "mongo":
        raise NotImplementedError("MongoDB storage is not implemented yet. Set STORAGE=memory.")
    else:
        raise ValueError(f"Unknown STORAGE configuration: {settings.STORAGE}")
