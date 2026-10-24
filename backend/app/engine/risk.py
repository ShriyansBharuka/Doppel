"""Risk fusion engine implementing Noisy-OR, sensitivity scaling, and floors per SPEC §7."""

import math
from typing import Optional

from app.models import (
    ASSET_MULTIPLIERS,
    Contribution,
    DetectorResult,
    Event,
    Sensitivity,
    SessionState,
    TaintLabel,
    Tier,
)
from app.world.egress import is_known

# Canonical detector weights per SPEC §7
DETECTOR_WEIGHTS: dict[str, float] = {
    "contract": 0.6,
    "novelty": 0.35,
    "sequence": 0.45,
    "taint_flow": 0.7,
    "decoy": 0.95,
    "drift_cusum": 0.5,
    "sigil": 0.8,
    "token_context": 0.7,
    "tool_integrity": 0.8,
}
WEIGHTS = DETECTOR_WEIGHTS


def derive_tier(session_risk: int) -> Tier:
    """Derive response tier from session risk score per SPEC §7.

    0–29 ALLOW · 30–59 WATCH · 60–79 SHRINK · 80–100 ISOLATE
    """
    if session_risk >= 80:
        return Tier.ISOLATE
    if session_risk >= 60:
        return Tier.SHRINK
    if session_risk >= 30:
        return Tier.WATCH
    return Tier.ALLOW


def fuse(
    results: list[DetectorResult],
    sensitivity: Optional[Sensitivity],
    session: SessionState,
    event: Optional[Event] = None,
) -> tuple[int, int, Tier, list[Contribution]]:
    """Fuse individual detector results into event risk, session risk, tier, and contributions.

    Formula:
      event_risk = min(100, round(100 × [1 − Π(1 − w_i·s_i)] × C))
    Floors:
      - decoy touch >= 90
      - watermark in egress = 100
      - missing/wrong sigil + sensitive read or egress >= 80
      - contract violation + egress to unknown host >= 80
      - chain floor = session.inherited_risk_floor
    Contributions:
      share_i = −ln(1 − w_i·s_i) / Σ_j −ln(1 − w_j·s_j), percentages summing to 100.
    """
    # 1. Noisy-OR calculation
    product = 1.0
    active_terms: list[tuple[DetectorResult, float]] = []

    for res in results:
        w = DETECTOR_WEIGHTS.get(res.name, 0.5)
        s = max(0.0, min(1.0, res.score))
        product *= (1.0 - w * s)
        if s > 0.0:
            term = -math.log(max(1e-9, 1.0 - w * s))
            active_terms.append((res, term))

    c_multiplier = ASSET_MULTIPLIERS.get(sensitivity, 1.0) if sensitivity else 1.0
    noisy_or_val = 100.0 * (1.0 - product) * c_multiplier
    event_risk = min(100, max(0, round(noisy_or_val)))

    # 2. Apply Floors (SPEC §7)
    d5_res = next((r for r in results if r.name == "decoy"), None)
    d1_res = next((r for r in results if r.name == "contract"), None)
    d7_res = next((r for r in results if r.name == "sigil"), None)

    # Floor: watermark in egress = 100 ("proven exfiltration")
    is_watermark_in_egress = False
    if d5_res and ("watermark_egress" in d5_res.flags or d5_res.score >= 1.0):
        if "watermark_egress" in d5_res.flags:
            is_watermark_in_egress = True
        else:
            for ev_line in d5_res.evidence:
                if "watermark" in ev_line.lower() or "exfiltration" in ev_line.lower():
                    is_watermark_in_egress = True
                    break

    if not is_watermark_in_egress and event is not None and event.action_type == "egress":
        from app.world.files import get_all_watermarks
        all_wms = get_all_watermarks().values()
        body_text = str(event.args)
        if any(wm in body_text for wm in all_wms) or "DPL-WM-" in body_text:
            is_watermark_in_egress = True

    if is_watermark_in_egress:
        event_risk = 100
    elif d5_res and ("decoy_touch" in d5_res.flags or d5_res.score >= 1.0):
        # Floor: decoy touch >= 90
        event_risk = max(event_risk, 90)

    # Floor: wrong/missing sigil + this call is sensitive read or egress >= 80 (Task 0.c)
    is_this_call_sensitive = sensitivity in (Sensitivity.confidential, Sensitivity.restricted)
    is_this_call_egress = event is not None and event.action_type == "egress"
    has_bad_sigil = (
        d7_res is not None
        and ("sigil_missing" in d7_res.flags or "sigil_wrong" in d7_res.flags or d7_res.score >= 0.9)
    )
    if has_bad_sigil and (is_this_call_sensitive or is_this_call_egress):
        event_risk = max(event_risk, 80)

    # Floor: contract violation + egress to unknown host >= 80 (this call's egress, not any earlier one)
    egress_to_unknown = (
        event is not None
        and event.action_type == "egress"
        and not is_known(str(event.target or "").split("@")[-1])
    )
    if d1_res and ("egress_unknown_host" in d1_res.flags or (d1_res.score >= 0.9 and egress_to_unknown)):
        event_risk = max(event_risk, 80)

    # Floor: chain inheritance
    event_risk = max(event_risk, session.inherited_risk_floor)
    event_risk = min(100, max(0, event_risk))

    # Session risk only moves up (except via human restore)
    session_risk = max(session.risk, event_risk)
    tier = derive_tier(session_risk)

    # 3. Calculate Contribution Shares
    contributions: list[Contribution] = []
    total_term = sum(t for _, t in active_terms)

    if total_term > 0.0 and active_terms:
        raw_shares = [(res, (term / total_term) * 100.0) for res, term in active_terms]
        rounded_shares = [(res, round(pct, 1)) for res, pct in raw_shares]
        diff = round(100.0 - sum(pct for _, pct in rounded_shares), 1)

        # Adjust the largest share so sum is exactly 100.0
        max_idx = max(range(len(rounded_shares)), key=lambda i: rounded_shares[i][1])
        adjusted_shares: list[tuple[DetectorResult, float]] = []
        for i, (res, pct) in enumerate(rounded_shares):
            if i == max_idx:
                adjusted_shares.append((res, round(pct + diff, 1)))
            else:
                adjusted_shares.append((res, pct))

        for res, pct in adjusted_shares:
            contributions.append(
                Contribution(
                    detector=res.name,
                    share_pct=pct,
                    score=res.score,
                    evidence=list(res.evidence),
                )
            )

    return event_risk, session_risk, tier, contributions
