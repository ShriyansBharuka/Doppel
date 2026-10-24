"""Base classes and typing protocols for drift detectors."""

from dataclasses import dataclass
from typing import Optional, Protocol, runtime_checkable

from app.clock import Clock
from app.config import Settings
from app.models import Contract, DetectorResult, Event, SessionState, ToolSpec, VirtualFile
from app.store import Store


@dataclass
class DetectorContext:
    """Execution context provided to each detector evaluation."""

    event: Event
    session: SessionState
    contract: Optional[Contract]
    tool_spec: Optional[ToolSpec]
    file: Optional[VirtualFile]
    store: Store
    clock: Clock
    settings: Settings


@runtime_checkable
class Detector(Protocol):
    """Protocol implemented by each individual detector D1..D9."""

    def detect(self, ctx: DetectorContext) -> DetectorResult:
        """Evaluate the event context and return a DetectorResult."""
        ...


# Registry of active detectors (empty stub for Prompt 3)
DETECTORS: list[Detector] = []
