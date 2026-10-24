"""Learned behavioral baseline, Markov transitions, and quarantine system."""

from collections import Counter, defaultdict
from dataclasses import dataclass, field
import logging
import math
from typing import TYPE_CHECKING, Optional

from app.scenarios.grammars import generate_benign_sessions

if TYPE_CHECKING:
    from app.models import Contract

logger = logging.getLogger(__name__)


def clamp(val: float, min_val: float, max_val: float) -> float:
    """Clamp value between min_val and max_val."""
    return max(min_val, min(val, max_val))


@dataclass
class QuarantineCandidate:
    """Tracks new behaviors quarantined until verified across 5 clean sessions."""

    key: str  # e.g. 'tool:vault.get' or 'transition:doc.read->vault.get'
    clean_sessions: set[str] = field(default_factory=set)
    tainted: bool = False


class BaselineEngine:
    """Learned behavioral baseline tracking tool frequency, Markov transitions, and quarantine."""

    def __init__(self) -> None:
        self.agent_tool_counts: dict[str, Counter[str]] = defaultdict(Counter)
        self.agent_transitions: dict[str, dict[str, Counter[str]]] = defaultdict(
            lambda: defaultdict(Counter)
        )
        self.agent_session_counts: Counter[str] = Counter()
        self.peer_tool_counts: Counter[str] = Counter()
        self.frozen_anchors: dict[str, dict[str, float]] = {}
        self.quarantine: dict[str, dict[str, QuarantineCandidate]] = defaultdict(dict)
        self.declared_tools: dict[str, set[str]] = defaultdict(set)
        self.declared_transitions: dict[str, set[tuple[str, str]]] = defaultdict(set)

    def reset(self) -> None:
        """Reset all learned counts, anchors, and quarantine tables."""
        self.agent_tool_counts.clear()
        self.agent_transitions.clear()
        self.agent_session_counts.clear()
        self.peer_tool_counts.clear()
        self.frozen_anchors.clear()
        self.quarantine.clear()
        self.declared_tools.clear()
        self.declared_transitions.clear()

    def train_sessions(
        self,
        agent_id: str,
        sessions: list[list[tuple[str, dict, str]]],
        set_anchor: bool = True,
    ) -> None:
        """Train baseline from a list of sessions (each a list of (tool, args, purpose))."""
        for session in sessions:
            self.agent_session_counts[agent_id] += 1
            prev_tool: Optional[str] = None
            for tool, _, _ in session:
                self.agent_tool_counts[agent_id][tool] += 1
                self.peer_tool_counts[tool] += 1
                if prev_tool:
                    self.agent_transitions[agent_id][prev_tool][tool] += 1
                prev_tool = tool

        if set_anchor:
            self.capture_frozen_anchor(agent_id)

    def capture_frozen_anchor(self, agent_id: str) -> None:
        """Capture the current normalized tool distribution as an immutable anchor."""
        counts = self.agent_tool_counts[agent_id]
        total = sum(counts.values())
        if total > 0:
            self.frozen_anchors[agent_id] = {t: c / total for t, c in counts.items()}
        else:
            self.frozen_anchors[agent_id] = {}

    def get_frozen_anchor(self, agent_id: str) -> dict[str, float]:
        """Return the immutable anchor tool distribution for an agent."""
        return dict(self.frozen_anchors.get(agent_id, {}))

    def apply_change_ticket(
        self,
        agent_id: str,
        new_tool: str,
        contract_tools: list[str],
    ) -> None:
        """Mark new tool and its transitions with existing contract tools as declared-known and re-capture frozen anchor per SPEC §4.3."""
        self.declared_tools[agent_id].add(new_tool)
        for t in contract_tools:
            if t != new_tool:
                self.declared_transitions[agent_id].add((t, new_tool))
                self.declared_transitions[agent_id].add((new_tool, t))
        self.capture_frozen_anchor(agent_id)

    # --- D2: Novelty Probabilities & Scoring ---

    def p_agent(self, agent_id: str, tool: str) -> float:
        """Return probability P_agent(tool) based on agent's learned tool counts."""
        counts = self.agent_tool_counts.get(agent_id, Counter())
        total = sum(counts.values())
        return counts[tool] / total if total > 0 else 0.0

    def p_peer(self, tool: str) -> float:
        """Return pooled peer prior probability P_peer(tool)."""
        total = sum(self.peer_tool_counts.values())
        return self.peer_tool_counts[tool] / total if total > 0 else 0.0

    def calculate_novelty_p(self, agent_id: str, tool: str) -> float:
        """Compute blended novelty probability: P = λ·P_agent(tool) + (1−λ)·P_peer(tool), λ = n/(n+50)."""
        if tool in self.declared_tools.get(agent_id, set()) and self.agent_tool_counts.get(agent_id, {}).get(tool, 0) == 0:
            return 0.25
        n = self.agent_session_counts[agent_id]
        lam = n / (n + 50) if n > 0 else 0.0
        p_ag = self.p_agent(agent_id, tool)
        p_pr = self.p_peer(tool)
        return lam * p_ag + (1.0 - lam) * p_pr

    def score_novelty(self, agent_id: str, tool: str) -> float:
        """Compute novelty anomaly score: clamp((−log2(P + 1e-6) − 2) / 10, 0, 1)."""
        # Tools declared in newer signed contract are treated as known by D2 for that agent until real data accumulates
        if tool in self.declared_tools.get(agent_id, set()) and self.agent_tool_counts.get(agent_id, {}).get(tool, 0) == 0:
            return 0.0

        p = self.calculate_novelty_p(agent_id, tool)
        raw_score = (-math.log2(p + 1e-6) - 2.0) / 10.0
        return clamp(raw_score, 0.0, 1.0)

    # --- D3: Sequence / Markov Transition Scoring ---

    def score_transition(
        self,
        agent_id: str,
        prev_tool: str,
        next_tool: str,
        contract: Optional["Contract"] = None,
    ) -> float:
        """Score transition P(next | prev).

        Unseen transition where both tools are in contract and common (P >= 0.05) -> 0.6.
        Unseen transition involving an off-contract or rare tool -> 0.8.
        P < 0.02 -> 0.5.
        Normal -> 0.0.
        """
        # Transitions declared in newer signed contract are treated as known by D3 for that agent until real data accumulates
        if (prev_tool, next_tool) in self.declared_transitions.get(agent_id, set()):
            if self.agent_transitions.get(agent_id, {}).get(prev_tool, {}).get(next_tool, 0) == 0:
                return 0.0

        trans_map = self.agent_transitions.get(agent_id, {}).get(prev_tool, Counter())
        total_transitions = sum(trans_map.values())

        if total_transitions == 0 or next_tool not in trans_map:
            both_on_contract = (
                contract is not None
                and prev_tool in contract.allowed_tools
                and next_tool in contract.allowed_tools
            )
            prev_p = self.calculate_novelty_p(agent_id, prev_tool)
            next_p = self.calculate_novelty_p(agent_id, next_tool)
            both_common = prev_p >= 0.05 and next_p >= 0.05

            if both_on_contract and both_common:
                return 0.6
            return 0.8

        p = trans_map[next_tool] / total_transitions
        if p < 0.02:
            return 0.5
        return 0.0

    # --- Baseline Quarantine (SPEC §6) ---

    def is_known_tool(self, agent_id: str, tool: str) -> bool:
        """Check if tool is part of the established agent baseline."""
        return (
            tool in self.agent_tool_counts.get(agent_id, Counter())
            or tool in self.declared_tools.get(agent_id, set())
        )

    def is_known_transition(self, agent_id: str, prev_tool: str, next_tool: str) -> bool:
        """Check if transition is part of established agent baseline."""
        return (
            next_tool in self.agent_transitions.get(agent_id, {}).get(prev_tool, Counter())
            or (prev_tool, next_tool) in self.declared_transitions.get(agent_id, set())
        )

    def record_quarantine_observation(
        self,
        agent_id: str,
        session_id: str,
        tool: str,
        prev_tool: Optional[str],
        has_untrusted_in: bool,
        session_risk: int,
    ) -> None:
        """Update quarantine state for unseen tools/transitions seen in a live session."""
        items_to_check: list[tuple[str, str, Optional[str]]] = []

        if not self.is_known_tool(agent_id, tool):
            items_to_check.append((f"tool:{tool}", tool, None))

        if prev_tool and not self.is_known_transition(agent_id, prev_tool, tool):
            items_to_check.append((f"trans:{prev_tool}->{tool}", tool, prev_tool))

        for key, t, p_t in items_to_check:
            cand = self.quarantine[agent_id].setdefault(key, QuarantineCandidate(key=key))

            if has_untrusted_in:
                # Poisoned session: permanently disqualified from joining baseline
                cand.tainted = True
                logger.info("Quarantine item %s permanently poisoned by UNTRUSTED_IN", key)
            elif not cand.tainted and session_risk < 30:
                cand.clean_sessions.add(session_id)
                # If observed in 5 clean sessions with risk < 30, promote to baseline!
                if len(cand.clean_sessions) >= 5:
                    self._promote_candidate(agent_id, key, t, p_t)

    def _promote_candidate(
        self,
        agent_id: str,
        key: str,
        tool: str,
        prev_tool: Optional[str],
    ) -> None:
        """Promote a quarantined candidate into the established baseline."""
        if key.startswith("tool:"):
            self.agent_tool_counts[agent_id][tool] += 5
            self.peer_tool_counts[tool] += 5
            logger.info("Promoted quarantined tool %s to baseline for %s", tool, agent_id)
        elif key.startswith("trans:") and prev_tool:
            self.agent_transitions[agent_id][prev_tool][tool] += 5
            logger.info("Promoted quarantined transition %s->%s to baseline for %s", prev_tool, tool, agent_id)

        self.quarantine[agent_id].pop(key, None)


_global_baseline = BaselineEngine()


def get_baseline() -> BaselineEngine:
    """Return the global BaselineEngine singleton."""
    return _global_baseline


def init_baseline(seed: int = 42) -> None:
    """Initialize baseline with 30 synthetic benign sessions per agent."""
    _global_baseline.reset()
    agents = ["procurement-agent", "email-triage-agent", "finance-agent"]
    for agent_id in agents:
        sessions = generate_benign_sessions(agent_id, n=30, seed=seed)
        _global_baseline.train_sessions(agent_id, sessions, set_anchor=True)
    logger.info("Initialized baseline with 30 sessions per agent (seed=%d)", seed)
