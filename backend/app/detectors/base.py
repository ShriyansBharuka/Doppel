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



def get_all_detectors() -> list["Detector"]:
    """Instantiate and return the list of 9 drift detectors D1..D9."""
    from app.detectors.d1_contract import ContractDetector
    from app.detectors.d2_novelty import NoveltyDetector
    from app.detectors.d3_sequence import SequenceDetector
    from app.detectors.d4_taint_flow import TaintFlowDetector
    from app.detectors.d5_decoy import DecoyDetector
    from app.detectors.d6_drift_cusum import DriftCusumDetector
    from app.detectors.d7_sigil import SigilDetector
    from app.detectors.d8_token_context import TokenContextDetector
    from app.detectors.d9_tool_integrity import ToolIntegrityDetector

    return [
        ContractDetector(),
        NoveltyDetector(),
        SequenceDetector(),
        TaintFlowDetector(),
        DecoyDetector(),
        DriftCusumDetector(),
        SigilDetector(),
        TokenContextDetector(),
        ToolIntegrityDetector(),
    ]


def __getattr__(name: str):
    if name == "DETECTORS":
        return get_all_detectors()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


