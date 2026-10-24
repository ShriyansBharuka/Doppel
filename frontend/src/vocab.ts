// Plain-English names shared by Two Views and the Case File. Keys are the backend's detector/tag/clause names.

/** The nine witnesses, in SPEC §6 order, with their SPEC §7 fusion weights. */
export const WITNESSES = [
  { id: "D1", name: "contract", label: "Contract", plain: "outside the signed role", weight: 0.6 },
  { id: "D2", name: "novelty", label: "Novelty", plain: "a tool this role rarely uses", weight: 0.35 },
  { id: "D3", name: "sequence", label: "Sequence", plain: "an unusual order of steps", weight: 0.45 },
  { id: "D4", name: "taint_flow", label: "Taint flow", plain: "untrusted input steering sensitive work", weight: 0.7 },
  { id: "D5", name: "decoy", label: "Decoy", plain: "touched a trap", weight: 0.95 },
  { id: "D6", name: "drift_cusum", label: "Slow drift", plain: "habits shifting over days", weight: 0.5 },
  { id: "D7", name: "sigil", label: "Sigil", plain: "intent canary missing or wrong", weight: 0.8 },
  { id: "D8", name: "token_context", label: "Token context", plain: "token used from somewhere new", weight: 0.7 },
  { id: "D9", name: "tool_integrity", label: "Tool integrity", plain: "a tool's definition changed", weight: 0.8 },
] as const;

/** Evidence from the witness that weighed most in fusion (weight × score), not merely the highest raw score. */
export function weightiestEvidence(results: { name: string; score: number; evidence: string[] }[]): string | null {
  const w = (n: string) => WITNESSES.find((x) => x.name === n)?.weight ?? 0.5;
  return (
    [...results].filter((d) => d.score > 0 && d.evidence.length).sort((a, b) => w(b.name) * b.score - w(a.name) * a.score)[0]
      ?.evidence[0] ?? null
  );
}

export const witnessLabel = (name: string) => WITNESSES.find((w) => w.name === name)?.label ?? name;

export const TAGS: Record<string, string> = {
  "OWASP:ASI01": "Agent Goal Hijack — injected instructions redirected what the agent was trying to do.",
  "OWASP:ASI02": "Tool Misuse — legitimate tools used for a purpose they weren't granted for.",
  "OWASP:ASI03": "Identity & Privilege Abuse — valid credentials used beyond the role, or by someone else.",
  "OWASP:ASI04": "Agentic Supply Chain — a tool changed after it was approved.",
  "OWASP:ASI07": "Insecure Inter-Agent Communication — a tainted instruction passed from one agent to another.",
  "OWASP:ASI10": "Rogue Agents — the agent acted against its owner and walked into a trap.",
  "ATLAS:AML.T0086": "Exfiltration via AI Agent Tool Invocation — data pushed out through the agent's own tools.",
  "ATLAS:AML.T0110": "AI Agent Tool Poisoning — a tool's definition altered to steer the agent.",
};

export const CLAUSES: Record<string, string> = {
  allowed_tools: "Allowed tools",
  allowed_data_classes: "Allowed data classes",
  egress_allowlist: "Egress allowlist",
  may_delegate_to: "May delegate to",
  rate_limit_per_min: "Rate limit per minute",
};
