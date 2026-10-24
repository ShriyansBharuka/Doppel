"""D1 Contract detector: validates actions against agent role contract."""

from typing import Optional
from urllib.parse import urlparse

from app.detectors.base import DetectorContext
from app.models import DetectorResult


def _extract_destination_host(target: Optional[str]) -> str:
    if not target:
        return ""
    target_clean = target.strip()
    if "@" in target_clean:
        return target_clean.split("@")[-1].lower()
    if "://" in target_clean:
        parsed = urlparse(target_clean)
        return (parsed.hostname or parsed.netloc).lower()
    return target_clean.split("/")[0].split(":")[0].lower()


class ContractDetector:
    """Detector D1: Verifies tool, data_class, egress, delegation, and rate limit against role contract."""

    name = "contract"

    def detect(self, ctx: DetectorContext) -> DetectorResult:
        contract = ctx.contract
        if not contract:
            return DetectorResult(
                name=self.name,
                score=1.0,
                evidence=["No signed role contract found for agent"],
                tags=["OWASP:ASI03"],
            )

        scores: list[tuple[float, str]] = []
        flags: set[str] = set()

        # 1. Tool check
        if ctx.event.tool not in contract.allowed_tools:
            scores.append((
                1.0,
                f"Tool '{ctx.event.tool}' is not in declared role contract allowed tools",
            ))
            flags.add("contract_violation")
            flags.add("tool_not_allowed")

        # 2. Data class check
        if ctx.event.data_class and ctx.event.data_class not in contract.allowed_data_classes:
            scores.append((
                1.0,
                f"Data class '{ctx.event.data_class}' is not in declared role contract allowed data classes",
            ))
            flags.add("contract_violation")
            flags.add("data_class_not_allowed")

        # 3. Egress host allowlist check
        if ctx.tool_spec and ctx.tool_spec.effect.value == "egress":
            host = _extract_destination_host(ctx.event.target)
            if host and host not in [h.lower() for h in contract.egress_allowlist]:
                scores.append((
                    0.9,
                    f"Egress host '{host}' is not on contract egress allowlist {contract.egress_allowlist}",
                ))
                flags.add("contract_violation")
                flags.add("egress_unknown_host")

        # 4. Delegation target check
        if ctx.event.tool == "agent.delegate":
            target_agent = str(ctx.event.args.get("target_agent", ""))
            if target_agent not in contract.may_delegate_to:
                scores.append((
                    0.9,
                    f"Delegation to '{target_agent}' not permitted by contract may_delegate_to {contract.may_delegate_to}",
                ))
                flags.add("contract_violation")
                flags.add("delegate_not_allowed")

        # 5. Rate limit check (calls in last 60 seconds)
        now_dt = ctx.clock.now()
        recent_calls = [
            ts for ts in ctx.session.recent_call_timestamps
            if (now_dt - ts).total_seconds() <= 60.0
        ]
        if len(recent_calls) > contract.rate_limit_per_min:
            scores.append((
                0.5,
                f"Rate limit exceeded: {len(recent_calls)} calls in last 60s (limit {contract.rate_limit_per_min})",
            ))
            flags.add("contract_violation")
            flags.add("rate_limit_exceeded")

        if not scores:
            return DetectorResult(
                name=self.name,
                score=0.0,
                evidence=[],
                tags=["OWASP:ASI03"],
                flags=set(),
            )

        max_score, top_evidence = max(scores, key=lambda x: x[0])
        return DetectorResult(
            name=self.name,
            score=max_score,
            evidence=[top_evidence],
            tags=["OWASP:ASI03"],
            flags=flags,
        )
