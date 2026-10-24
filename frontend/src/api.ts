// Typed client for the Doppel backend. Shapes mirror backend/app/models.py and the route handlers.

import { weightiestEvidence } from "./vocab";

export const API_URL = (import.meta.env.VITE_API_URL ?? "http://localhost:8000").replace(/\/$/, "");
export const WS_URL = API_URL.replace(/^http/, "ws") + "/v1/stream";

export type Tier = "ALLOW" | "WATCH" | "SHRINK" | "ISOLATE";
export type Decision = "allow" | "hold" | "sinkhole" | "decoy" | "block" | "shrink" | "isolate";

export interface Health {
  status: string;
  contracts_loaded: number;
  tools_pinned: number;
}

export interface Agent {
  agent_id: string;
  role: string;
  purpose: string;
  contract_version: number;
  signature_valid: boolean;
}

export interface AgentDetail {
  agent_id: string;
  role: string;
  purpose: string;
  contract_version: number;
  sessions: string[];
  max_risk: number;
}

export interface TaintRef {
  content_id: string;
  source: string;
  sha256: string;
  ts: string;
}

export interface DetectorResult {
  name: string;
  score: number;
  evidence: string[];
  tags: string[];
  side_effects: string[];
  flags: string[];
}

export interface DoppelEvent {
  event_id: string;
  session_id: string;
  agent_id: string;
  tool: string;
  args: Record<string, unknown>;
  purpose: string;
  timestamp: string;
  action_type: string | null;
  target: string | null;
  data_class: string | null;
  sensitivity: string | null;
  bytes_out: number;
  sigil_status: string;
  sigil_present: boolean;
  runtime_fingerprint: string | null;
  token_jti: string | null;
  taint_labels_snapshot: string[];
  taint_refs_snapshot: TaintRef[];
  decision: Decision;
  risk: number;
  tier: Tier;
  detector_results: DetectorResult[];
  result: unknown;
  latency_ms: number;
}

export interface Contribution {
  detector: string;
  share_pct: number;
  score: number;
  evidence: string[];
}

export interface RootCause {
  content_id: string;
  source: string;
  sha256: string;
  ts: string;
  link_reason: string;
}

export interface DriftReceipt {
  alert_id: string;
  agent_id: string;
  session_id: string;
  risk: number;
  tier: Tier;
  headline: string;
  headline_short: string;
  contributions: Contribution[];
  root_cause: RootCause | null;
  contract_clause: string | null;
  actions_taken: string[];
  undo: string | null;
  tags: string[];
  timeline: string[];
}

export interface Alert {
  alert_id: string;
  session_id: string;
  agent_id: string;
  risk: number;
  tier: Tier;
  headline: string;
  receipt: DriftReceipt | null;
  created_at: string;
  status: string;
}

export interface Approval {
  approval_id: string;
  alert_id: string | null;
  session_id: string;
  event_id: string;
  agent_id: string;
  tool: string;
  args: Record<string, unknown>;
  purpose: string;
  status: "pending" | "approved" | "denied";
  note: string | null;
  created_at: string;
  resolved_at: string | null;
}

export interface SinkholeCapture {
  capture_id: string;
  session_id: string;
  agent_id: string;
  tool: string;
  host: string;
  destination: string;
  payload: unknown;
  bytes: number;
  matched_watermarks: string[];
  leaked_decoy: string | null;
  watermark_detected: string | null;
  timestamp: string;
}

/** Console view of a session; the backend strips sigil and tokens. */
export interface Session {
  session_id: string;
  agent_id: string;
  contract_version: number;
  original_fingerprint: string;
  runtime_fingerprint: string;
  current_jti: string;
  parent_session_id: string | null;
  inherited_risk_floor: number;
  taint_labels: string[];
  taint_refs: TaintRef[];
  risk: number;
  tier: Tier;
  frozen: boolean;
  decoy_mode: boolean;
  removed_scopes: string[];
  snapshot_event_ids: string[];
  alert_id: string | null;
  act: string[];
  call_count: number;
  created_at: string;
  updated_at: string;
}

export interface WorldFile {
  path: string;
  data_class: string;
  trust: "trusted" | "untrusted";
  is_decoy: boolean;
  has_watermark: boolean;
}

export interface WorldTool {
  name: string;
  description: string;
  params: Record<string, unknown>;
  effect: "read" | "write" | "egress" | "delegate";
  data_class: string | null;
  is_decoy: boolean;
  schema_hash: string;
}

export interface EgressEntry {
  host: string;
  bytes: number;
  body: string;
  ts: string;
}

export interface WorldState {
  purchase_requests: Record<string, unknown>[];
  payments: Record<string, unknown>[];
  egress_log: EgressEntry[];
  delegations: Delegation[];
}

export interface Meta {
  version: string;
  mode: string;
  scenarios_available: string[];
  /** followed_injection is the string "True" / "False". */
  live_recording: { model: string; date: string; followed_injection: string; agent_config: string } | null;
  live_campaign: Campaign | null;
  agent_config: string;
}

interface CampaignCounts {
  runs: number;
  followed: number;
  caught_of_followed: number;
  false_alarms_on_resisted: number;
}

/** One (model, injection variant, agent config) cell of the live campaign. */
export interface CampaignEntry extends CampaignCounts {
  model: string;
  variant: number;
  agent_config: string;
}

/** recordings/campaign.json, written by backend/app/agents/run_live.py. */
export interface Campaign {
  date: string;
  entries: CampaignEntry[];
  total: CampaignCounts;
}

/** frontend/public/results.json — the output of backend/app/eval/run_eval.py --out. */
type TierCounts = { WATCH: number; SHRINK: number; ISOLATE: number };

interface BenignSlice {
  total_sessions: number;
  false_alarms: number;
  false_alarms_per_100: number;
  by_tier: TierCounts;
  by_tier_per_100: TierCounts;
}

export interface LearningBlock {
  block: number;
  range: string;
  sessions: number;
  false_alarms: number;
  fa_per_100: number;
}

export interface EvalResults {
  benchmark: string;
  environment: string;
  /** Headline numbers are the perturbed (realistic-noise) run; `unperturbed` is the clean comparison. */
  benign: {
    total_benign_sessions: number;
    false_alarms: number;
    false_alarms_per_100: number;
    by_tier: TierCounts;
    by_tier_per_100: TierCounts;
    held_actions: { count: number; total_calls: number; pct_of_all_calls: number };
    unperturbed: BenignSlice;
    perturbed: BenignSlice;
    learning_curve: {
      first_half_fa_count: number;
      first_half_sessions: number;
      first_half_fa_per_100: number;
      second_half_fa_count: number;
      second_half_sessions: number;
      second_half_fa_per_100: number;
      blocks_of_25: LearningBlock[];
    };
    /** Free text written by run_eval.py, not a per-detector measurement. */
    trigger_analysis: string;
  };
  attacks: {
    families: Record<
      string,
      {
        variants_tested: number;
        detected: number;
        detection_rate_pct: number;
        median_actions_to_detect: number | null;
        real_bytes_leaked: number;
        median_alarm_day?: number;
      }
    >;
    overall_variants_tested: number;
    overall_detected: number;
    overall_detection_rate_pct: number;
    overall_median_actions_to_detect: number | null;
    real_bytes_leaked: number;
  };
  latency_ms: { p50: number; p95: number; samples: number };
}

/** Static file served by the frontend itself; null when the eval hasn't been dropped in yet. */
export async function loadResults(): Promise<EvalResults | null> {
  const res = await fetch("/results.json", { cache: "no-store" });
  // Vite dev and SPA rewrites answer unknown paths with index.html, so check the type, not just the status.
  if (!res.ok || !res.headers.get("content-type")?.includes("json")) return null;
  return res.json();
}

export interface ContentSegment {
  text: string;
  hidden: boolean;
}

export interface WorldContent {
  path: string;
  data_class: string;
  trust: "trusted" | "untrusted";
  is_decoy: boolean;
  segments: ContentSegment[];
  content: string;
}

export interface Contract {
  agent_id: string;
  role: string;
  purpose: string;
  owner: string;
  version: number;
  allowed_tools: string[];
  allowed_data_classes: string[];
  egress_allowlist: string[];
  may_delegate_to: string[];
  rate_limit_per_min: number;
}

export interface Delegation {
  from_session: string;
  to_agent: string;
  instruction: string;
  ts: string;
}

export interface ScenarioMeta {
  id: string;
  name: string;
  description: string;
  expected_outcome: string;
}

export interface ScenarioStep {
  step_number: number;
  agent_id: string;
  tool: string;
  args: Record<string, unknown>;
  purpose: string;
  /** model_text: what the live model said before this call (S1L replays only). */
  agent_view: { status?: string; result?: unknown; new_token?: string | null; model_text?: string | null };
  defender_view: {
    decision: Decision | "unknown";
    risk: number;
    session_risk: number;
    tier: Tier;
    top_evidence: string[];
    alert_id: string | null;
    sinkhole_capture_id: string | null;
    taint_labels: string[];
    event_id?: string;
  };
}

export interface ScenarioResult {
  id: string;
  name: string;
  description: string;
  steps: ScenarioStep[];
  expected: string;
  passed: boolean;
  alert_ids: string[];
  capture_ids: string[];
  summary: string;
}

export interface S5Day {
  day: number;
  divergence: number;
  cusum: number;
  h: number;
  cusum_alarm: boolean;
  ewma_score: number;
  ewma_alarm: boolean;
  ewma_threshold: number;
  max_event_risk_without_d6: number;
}

/** GET /v1/scenarios/s5/series — thresholds fitted on the training days, plus the 30 monitored days. */
export interface S5Data {
  h: number;
  ewma_threshold: number;
  series: S5Day[];
}

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

async function req<T>(path: string, init?: RequestInit & { timeoutMs?: number }): Promise<T> {
  const res = await fetch(API_URL + path, {
    ...init,
    headers: { "Content-Type": "application/json", ...init?.headers },
    signal: init?.timeoutMs ? AbortSignal.timeout(init.timeoutMs) : init?.signal,
  });
  if (!res.ok) throw new ApiError(res.status, await res.text());
  return res.json() as Promise<T>;
}

const post = <T>(path: string, body?: unknown) =>
  req<T>(path, { method: "POST", body: body === undefined ? undefined : JSON.stringify(body) });

const orNull = <T>(p: Promise<T>) =>
  p.catch((err) => {
    if (err instanceof ApiError && err.status === 404) return null;
    throw err;
  });

const q = (sessionId?: string) => (sessionId ? `?session_id=${encodeURIComponent(sessionId)}` : "");
const e = encodeURIComponent;

export const api = {
  health: (timeoutMs = 8000) => req<Health>("/health", { timeoutMs }),
  meta: () => req<Meta>("/v1/meta"),

  agents: () => req<Agent[]>("/v1/agents"),
  agent: (id: string) => req<AgentDetail>(`/v1/agents/${e(id)}`),

  session: (id: string) => req<Session>(`/v1/sessions/${e(id)}`),
  freeze: (id: string) => post<{ status: string; session_id: string }>(`/v1/sessions/${e(id)}/freeze`),
  restore: (id: string) => post<{ status: string; session_id: string }>(`/v1/sessions/${e(id)}/restore`),

  events: (sessionId?: string) => req<DoppelEvent[]>(`/v1/events${q(sessionId)}`),
  alerts: (sessionId?: string) => req<Alert[]>(`/v1/alerts${q(sessionId)}`),
  alert: (id: string) => req<Alert>(`/v1/alerts/${e(id)}`),
  receipt: (id: string) => req<DriftReceipt>(`/v1/alerts/${e(id)}/receipt`),
  approvals: (status?: string, sessionId?: string) => {
    const p = new URLSearchParams();
    if (status) p.set("status", status);
    if (sessionId) p.set("session_id", sessionId);
    return req<Approval[]>(`/v1/approvals${p.size ? `?${p}` : ""}`);
  },
  /** id may be an approval_id or an alert_id (backend resolves the pending approval). */
  approve: (id: string) => post<{ status: string; approval_id: string; result: unknown }>(`/v1/alerts/${e(id)}/approve`),
  deny: (id: string) => post<{ status: string; approval_id: string }>(`/v1/alerts/${e(id)}/deny`),
  reapproveTool: (name: string) =>
    post<{ status: string; tool: string; schema_hash: string }>(`/v1/tools/${e(name)}/reapprove`),

  contract: (agentId: string) => req<Contract>(`/v1/agents/${e(agentId)}/contract`),

  sinkhole: () => req<SinkholeCapture[]>("/v1/sinkhole"),
  /** Hidden-text segments with watermarks masked; null on 404 (unknown path or older backend). */
  worldContent: (path: string) => orNull(req<WorldContent>(`/v1/world/content?path=${e(path)}`)),
  worldFiles: () => req<WorldFile[]>("/v1/world/files"),
  worldTools: () => req<WorldTool[]>("/v1/world/tools"),
  worldState: () => req<WorldState>("/v1/world/state"),

  scenarios: () => req<ScenarioMeta[]>("/v1/scenarios"),
  runScenario: (id: string, opts: { reset?: boolean; step_delay_ms?: number } = {}) =>
    post<{ run_id: string; status: string; scenario_id: string }>(`/v1/scenarios/${e(id)}/run`, {
      reset: opts.reset ?? true,
      step_delay_ms: opts.step_delay_ms ?? 700,
    }),
  /** 404 while the run is still in progress. */
  scenarioRun: (runId: string) => req<ScenarioResult>(`/v1/scenarios/runs/${e(runId)}`),
  s5Series: () => req<S5Data>("/v1/scenarios/s5/series"),

  reset: () => post<{ status: string; contracts_loaded: number; tools_pinned: number }>("/v1/reset"),
};

/** Messages the backend pushes on WS /v1/stream (see backend/app/stream.py callers). */
export type StreamMessage =
  | { type: "event"; data: DoppelEvent }
  | { type: "alert"; data: Alert }
  | { type: "approval"; data: Approval }
  | { type: "sinkhole"; data: SinkholeCapture }
  | { type: "tool_disabled"; data: { tool: string } }
  | { type: "scenario_step"; data: { scenario_id: string; run_id?: string; step: ScenarioStep } }
  | { type: "scenario_done"; data: { scenario_id: string; run_id?: string; result: ScenarioResult } }
  | { type: "pong"; data: Record<string, never> };

export const tierOf = (risk: number): Tier =>
  risk >= 80 ? "ISOLATE" : risk >= 60 ? "SHRINK" : risk >= 30 ? "WATCH" : "ALLOW";

/** Backend sends ISO strings over HTTP and str(datetime) over WS; both contain HH:MM:SS. */
export const clockTime = (ts: string) => ts.match(/\d{2}:\d{2}:\d{2}/)?.[0] ?? ts;

/** Union of every agent's egress_allowlist. */
export async function allowedHosts(): Promise<Set<string>> {
  const agents = await api.agents();
  const contracts = await Promise.all(agents.map((a) => api.contract(a.agent_id)));
  return new Set(contracts.flatMap((c) => c.egress_allowlist).map((h) => h.toLowerCase()));
}

/** Bytes that reached a host no agent is allowed to talk to — data actually stolen. */
export const stolenBytes = (log: EgressEntry[], allowed: Set<string>) =>
  log.filter((e) => !allowed.has(e.host.toLowerCase())).reduce((n, e) => n + (e.bytes || 0), 0);

/** Match the backend's policy for /world/files and /world/content: never display a watermark value. */
export const maskWatermarks = (s: string) => s.replace(/DPL-WM-[0-9A-Fa-f]{12}/g, "DPL-WM-••••");

/** Evidence of the top-contributing detector (fusion weight × score, SPEC §7), watermarks masked. */
export const topEvidence = (ev: DoppelEvent) => {
  const line = weightiestEvidence(ev.detector_results);
  return line ? maskWatermarks(line) : null;
};
