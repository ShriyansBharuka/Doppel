"""D4 Taint Flow detector: enforces Rule of Two across tainted execution paths."""

from app.detectors.base import DetectorContext
from app.models import DetectorResult, Sensitivity, TaintLabel, Trust


class TaintFlowDetector:
    """Detector D4: Flags correlation of untrusted inputs with sensitive reads, egress, or delegations."""

    name = "taint_flow"

    def detect(self, ctx: DetectorContext) -> DetectorResult:
        session = ctx.session
        has_untrusted = (
            TaintLabel.UNTRUSTED_IN in session.taint_labels
            or (ctx.file is not None and ctx.file.trust == Trust.untrusted)
        )

        if not has_untrusted:
            return DetectorResult(
                name=self.name,
                score=0.0,
                evidence=[],
                tags=["ATLAS:AML.T0086"],
            )

        source_info = (
            session.taint_refs[-1].source
            if session.taint_refs
            else (ctx.file.path if ctx.file else "untrusted source")
        )

        is_egress = (
            (ctx.tool_spec and ctx.tool_spec.effect.value == "egress")
            or TaintLabel.EGRESS in session.taint_labels
        )
        is_sensitive = (
            TaintLabel.SENSITIVE_READ in session.taint_labels
            or (ctx.event.sensitivity in (Sensitivity.confidential, Sensitivity.restricted))
        )
        touches_sensitive = ctx.event.sensitivity in (Sensitivity.confidential, Sensitivity.restricted)
        is_delegate = ctx.event.tool == "agent.delegate"
        is_write = ctx.tool_spec and ctx.tool_spec.effect.value == "write"

        scores: list[tuple[float, str]] = []

        # 1. UNTRUSTED_IN + SENSITIVE_READ + egress -> 0.9
        if is_sensitive and is_egress:
            scores.append((
                0.9,
                f"Untrusted input ({source_info}) combined with sensitive data access and attempted egress",
            ))

        # 2. UNTRUSTED_IN + write/egress touching sensitive class -> 0.6
        if (is_write or is_egress) and touches_sensitive:
            scores.append((
                0.6,
                f"Untrusted input ({source_info}) combined with {ctx.event.tool} touching sensitive class '{ctx.event.data_class}'",
            ))

        # 3. UNTRUSTED_IN + delegate -> 0.3
        if is_delegate:
            target = ctx.event.args.get("target_agent", "agent")
            scores.append((
                0.3,
                f"Untrusted input ({source_info}) followed by delegation to {target}",
            ))

        # 4. UNTRUSTED_IN + SENSITIVE_READ -> 0.3
        if is_sensitive:
            scores.append((
                0.3,
                f"Untrusted input ({source_info}) combined with sensitive read of '{ctx.event.data_class or 'sensitive data'}'",
            ))

        if not scores:
            return DetectorResult(
                name=self.name,
                score=0.0,
                evidence=[],
                tags=["ATLAS:AML.T0086"],
            )

        max_score, top_evidence = max(scores, key=lambda x: x[0])
        return DetectorResult(
            name=self.name,
            score=max_score,
            evidence=[top_evidence],
            tags=["ATLAS:AML.T0086"],
        )
