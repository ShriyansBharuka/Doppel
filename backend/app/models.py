"""Domain models and enums covering Doppel SPEC §4–§9."""

from datetime import datetime
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field


# --- Enums ---

class Sensitivity(str, Enum):
    """Data sensitivity classification (SPEC §4.2)."""
    public = "public"
    internal = "internal"
    confidential = "confidential"
    restricted = "restricted"


DATA_CLASS_SENSITIVITY: dict[str, Sensitivity] = {
    "product_catalog": Sensitivity.public,
    "supplier_data": Sensitivity.internal,
    "purchase_requests": Sensitivity.internal,
    "email": Sensitivity.internal,
    "hr_directory": Sensitivity.confidential,
    "hr_salary": Sensitivity.restricted,
    "vendor_bank": Sensitivity.restricted,
    "payments": Sensitivity.restricted,
    "secrets": Sensitivity.restricted,
}

ASSET_MULTIPLIERS: dict[Sensitivity, float] = {
    Sensitivity.public: 0.8,
    Sensitivity.internal: 1.0,
    Sensitivity.confidential: 1.2,
    Sensitivity.restricted: 1.2,
}


class Trust(str, Enum):
    """Data trust origin (SPEC §4.4)."""
    trusted = "trusted"
    untrusted = "untrusted"


class Effect(str, Enum):
    """Tool execution effect classification (SPEC §4.4)."""
    read = "read"
    write = "write"
    egress = "egress"
    delegate = "delegate"


class Tier(str, Enum):
    """Security tier response ladder (SPEC §7, §8)."""
    ALLOW = "ALLOW"
    WATCH = "WATCH"
    SHRINK = "SHRINK"
    ISOLATE = "ISOLATE"


class Decision(str, Enum):
    """Gateway pipeline decision (SPEC §5, §8)."""
    allow = "allow"
    hold = "hold"
    sinkhole = "sinkhole"
    decoy = "decoy"
    block = "block"
    shrink = "shrink"
    isolate = "isolate"


class TaintLabel(str, Enum):
    """Session taint labels (SPEC §5)."""
    UNTRUSTED_IN = "UNTRUSTED_IN"
    SENSITIVE_READ = "SENSITIVE_READ"
    EGRESS = "EGRESS"


# --- Core Models ---

class Contract(BaseModel):
    """Signed role contract governing an agent (SPEC §4.3)."""
    agent_id: str
    role: str
    purpose: str
    owner: str
    version: int = 1
    allowed_tools: list[str] = Field(default_factory=list)
    allowed_data_classes: list[str] = Field(default_factory=list)
    egress_allowlist: list[str] = Field(default_factory=list)
    may_delegate_to: list[str] = Field(default_factory=list)
    rate_limit_per_min: int = 30
    signature: str = ""


class ToolSpec(BaseModel):
    """Specification of a simulated tool (SPEC §4.4)."""
    name: str
    description: str
    params: dict[str, Any] = Field(default_factory=dict)
    effect: Effect
    data_class: Optional[str] = None
    is_decoy: bool = False
    schema_hash: str = ""


class VirtualFile(BaseModel):
    """Virtual file within the simulated world (SPEC §4.4)."""
    path: str
    data_class: str
    trust: Trust
    is_decoy: bool
    watermark: Optional[str] = None
    content: str


class TaintRef(BaseModel):
    """Reference tracking tainted content read by a session (SPEC §5)."""
    content_id: str
    source: str
    sha256: str
    ts: datetime


class DetectorResult(BaseModel):
    """Individual detector outcome (SPEC §6)."""
    name: str
    score: float = Field(ge=0.0, le=1.0)
    evidence: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    side_effects: list[str] = Field(default_factory=list)


class Event(BaseModel):
    """Auditable gateway event (SPEC §5)."""
    event_id: str
    session_id: str
    agent_id: str
    tool: str
    args: dict[str, Any] = Field(default_factory=dict)
    purpose: str = ""
    timestamp: datetime
    action_type: Optional[str] = None
    target: Optional[str] = None
    data_class: Optional[str] = None
    sensitivity: Optional[Sensitivity] = None
    bytes_out: int = 0
    sigil_status: str = "valid"
    sigil_present: bool = False
    runtime_fingerprint: Optional[str] = None
    token_jti: Optional[str] = None
    taint_labels_snapshot: list[TaintLabel] = Field(default_factory=list)
    taint_refs_snapshot: list[TaintRef] = Field(default_factory=list)
    decision: Decision = Decision.allow
    risk: int = Field(default=0, ge=0, le=100)
    tier: Tier = Tier.ALLOW
    detector_results: list[DetectorResult] = Field(default_factory=list)
    result: Optional[Any] = None
    latency_ms: float = 0.0


class Contribution(BaseModel):
    """Contribution share of an individual detector to risk score (SPEC §9)."""
    detector: str
    share_pct: float
    score: float
    evidence: list[str] = Field(default_factory=list)


class RootCause(BaseModel):
    """Root-cause trace for drift alert (SPEC §9)."""
    content_id: str
    source: str
    sha256: str
    ts: datetime
    link_reason: str


class DriftReceipt(BaseModel):
    """Explainable drift receipt generated for alerts (SPEC §9)."""
    alert_id: str
    agent_id: str
    session_id: str
    risk: int
    tier: Tier
    headline: str
    contributions: list[Contribution] = Field(default_factory=list)
    root_cause: Optional[RootCause] = None
    contract_clause: Optional[str] = None
    actions_taken: list[str] = Field(default_factory=list)
    undo: Optional[str] = None
    tags: list[str] = Field(default_factory=list)
    timeline: list[str] = Field(default_factory=list)


class SessionState(BaseModel):
    """Session state tracked by the gateway (SPEC §5, §7, §8)."""
    session_id: str
    agent_id: str
    token: str = ""
    sigil: str = ""
    contract_version: int = 1
    original_fingerprint: str = ""
    runtime_fingerprint: str = ""
    current_jti: str = ""
    parent_session_id: Optional[str] = None
    inherited_risk_floor: int = Field(default=0, ge=0, le=100)  # 0.7 × parent risk at delegation (SPEC §7)
    taint_labels: list[TaintLabel] = Field(default_factory=list)
    taint_refs: list[TaintRef] = Field(default_factory=list)
    risk: int = Field(default=0, ge=0, le=100)
    tier: Tier = Tier.ALLOW
    frozen: bool = False
    decoy_mode: bool = False
    removed_scopes: list[str] = Field(default_factory=list)
    snapshot_event_ids: list[str] = Field(default_factory=list)
    alert_id: Optional[str] = None
    pending_new_token: Optional[str] = None
    act: list[str] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime
    recent_call_timestamps: list[datetime] = Field(default_factory=list)


class SinkholeCapture(BaseModel):
    """Captured payload sent to the sinkhole honeypot (SPEC §8)."""
    capture_id: str
    session_id: str
    agent_id: str
    tool: str
    host: str = ""
    destination: str = ""
    payload: Any = None
    bytes: int = 0
    matched_watermarks: list[str] = Field(default_factory=list)
    leaked_decoy: Optional[str] = None
    watermark_detected: Optional[str] = None
    timestamp: datetime


class Approval(BaseModel):
    """Pending or resolved human approval request (SPEC §8)."""
    approval_id: str
    alert_id: Optional[str] = None
    session_id: str
    event_id: str
    agent_id: str = ""
    tool: str
    args: dict[str, Any] = Field(default_factory=dict)
    purpose: str = ""
    status: str = "pending"  # pending, approved, denied
    note: Optional[str] = None
    created_at: datetime
    resolved_at: Optional[datetime] = None


class Alert(BaseModel):
    """Drift alert emitted when tier >= WATCH (SPEC §5, §7, §9)."""
    alert_id: str
    session_id: str
    agent_id: str
    risk: int
    tier: Tier
    headline: str
    receipt: Optional[DriftReceipt] = None
    created_at: datetime
    status: str = "open"
