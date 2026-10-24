"""D9 Tool Integrity detector: detects tool rug pulls and parameter poisoning."""

from app.detectors.base import DetectorContext
from app.models import DetectorResult
from app.world.tools import compute_schema_hash, get_tool


class ToolIntegrityDetector:
    """Detector D9: Compares live schema hash against pinned hash to detect tool poisoning (S2 rug pull)."""

    name = "tool_integrity"

    def detect(self, ctx: DetectorContext) -> DetectorResult:
        tool_name = ctx.event.tool
        pinned_hash = ctx.store.get_pinned_tool_hash(tool_name)
        live_tool = get_tool(tool_name)

        if pinned_hash and live_tool:
            # Hash what is live now; the cached schema_hash field is whatever the (possibly hostile) definition claims
            live_hash = compute_schema_hash(live_tool.name, live_tool.description, live_tool.params)
            if live_hash != pinned_hash:
                return DetectorResult(
                    name=self.name,
                    score=0.8,
                    evidence=[
                        f"Tool schema integrity violation: live hash '{live_hash[:12]}...' "
                        f"of '{tool_name}' does not match pinned hash '{pinned_hash[:12]}...'"
                    ],
                    tags=["OWASP:ASI04", "ATLAS:AML.T0110"],
                    side_effects=[f"disable_tool:{tool_name}"],
                    flags={"tool_integrity_violation"},
                )

        return DetectorResult(
            name=self.name,
            score=0.0,
            evidence=[],
            tags=["OWASP:ASI04", "ATLAS:AML.T0110"],
            flags=set(),
        )
