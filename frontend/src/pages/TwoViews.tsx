import { useCallback, useEffect, useRef, useState } from "react";
import { useNavigate, useParams, useSearchParams } from "react-router-dom";
import {
  allowedHosts,
  api,
  ApiError,
  stolenBytes,
  type DoppelEvent,
  type ScenarioResult,
  type ScenarioStep,
  type StreamMessage,
} from "../api";
import { useStream } from "../useStream";
import { Header } from "../components/Header";
import { Button, Label } from "../components/ui";
import { AgentTerminal, type PairedStep } from "../components/twoviews/AgentTerminal";
import { DefenderPanel } from "../components/twoviews/DefenderPanel";
import { FinalBanner } from "../components/twoviews/FinalBanner";

const STEP_DELAY_MS = 700; // backend pacing; the player below sets the on-screen pace
const STEP_MS = 1600; // on-screen time per step at 1×
const SPEEDS = [0.5, 1, 2] as const;

type Status = "starting" | "live" | "done" | "missing" | "error";

const ViewTitle = ({ title, plain }: { title: string; plain: string }) => (
  <div className="mb-3 flex flex-wrap items-baseline gap-x-4">
    <h2 className="font-display text-[28px] leading-tight font-semibold">{title}</h2>
    <p className="text-[15px] text-bone-dim italic">{plain}</p>
  </div>
);

/** For runs loaded after the fact: match each step to the event record_step read (same agent, tool, risk, decision). */
function pairFromEvents(steps: ScenarioStep[], events: DoppelEvent[]): PairedStep[] {
  let from = 0;
  return steps.map((step) => {
    const dv = step.defender_view;
    const i = dv.event_id
      ? events.findIndex((e) => e.event_id === dv.event_id)
      : events.findIndex(
          (e, j) => j >= from && e.agent_id === step.agent_id && e.tool === step.tool && e.risk === dv.risk && e.decision === dv.decision,
        );
    if (i < 0) return { step };
    from = i + 1;
    return { step, event: events[i] };
  });
}

export default function TwoViews() {
  const { runId = "new" } = useParams();
  const [params] = useSearchParams();
  const scenarioId = params.get("s") ?? "";
  const navigate = useNavigate();

  const [status, setStatus] = useState<Status>(runId === "new" ? "starting" : "live");
  const [steps, setSteps] = useState<PairedStep[]>([]);
  const [result, setResult] = useState<ScenarioResult | null>(null);
  const [stolen, setStolen] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [cursor, setCursor] = useState(0);
  const [playing, setPlaying] = useState(true);
  const [speed, setSpeed] = useState<(typeof SPEEDS)[number]>(1);

  // Which run's stream messages belong on this page. run_id wins when the backend sends one.
  const live = useRef<{ scenario: string; runId: string | null } | null>(
    runId === "new" ? null : { scenario: scenarioId, runId },
  );
  const lastEvent = useRef<Record<string, DoppelEvent>>({});
  const launched = useRef(false);

  const finish = useCallback((r: ScenarioResult) => {
    live.current = null;
    setResult(r);
    // S4/S6 currently return no steps in the result; keep what streamed in.
    setSteps((s) => (s.length ? s : r.steps.map((step) => ({ step }))));
    setStatus("done");
    Promise.all([api.worldState(), allowedHosts()]).then(
      ([w, hosts]) => setStolen(stolenBytes(w.egress_log, hosts)),
      () => setStolen(null),
    );
  }, []);

  const belongs = (d: { scenario_id: string; run_id?: string }) => {
    const l = live.current;
    if (!l) return false;
    if (d.run_id && l.runId) return d.run_id === l.runId;
    return d.scenario_id === l.scenario;
  };

  const stream = useStream((m: StreamMessage) => {
    if (m.type === "event") lastEvent.current[m.data.agent_id] = m.data;
    else if (m.type === "scenario_step" && belongs(m.data)) {
      const step = m.data.step;
      const ev = lastEvent.current[step.agent_id];
      setSteps((s) => [...s, { step, event: ev?.tool === step.tool ? ev : undefined }]);
      setStatus((st) => (st === "starting" ? "live" : st));
    } else if (m.type === "scenario_done" && belongs(m.data)) finish(m.data.result);
  });

  // /scenario/new?s=s1 — listen first, then launch, then put the real run_id in the URL.
  useEffect(() => {
    if (runId === "new" && !scenarioId) setStatus("missing");
    if (runId !== "new" || launched.current || stream !== "open" || !scenarioId) return;
    launched.current = true;
    live.current = { scenario: scenarioId, runId: null };
    api
      .runScenario(scenarioId, { reset: true, step_delay_ms: STEP_DELAY_MS })
      .then(({ run_id }) => {
        if (live.current) live.current.runId = run_id;
        navigate(`/scenario/${run_id}?s=${scenarioId}`, { replace: true });
      })
      .catch((e) => {
        setStatus("error");
        setError(`Couldn't start ${scenarioId.toUpperCase()}: ${e.message}`);
      });
  }, [runId, stream, scenarioId, navigate]);

  // Opened by link or reload: load the finished run, or keep listening if it's still going.
  useEffect(() => {
    if (runId === "new" || launched.current) return;
    let cancelled = false;
    (async () => {
      try {
        const r = await api.scenarioRun(runId);
        if (cancelled) return;
        const events = await api.events().catch(() => []);
        live.current = null;
        setSteps(pairFromEvents(r.steps, events));
        finish(r);
      } catch (e) {
        if (!(e instanceof ApiError && e.status === 404)) setError((e as Error).message);
        else if (!scenarioId) setStatus("missing");
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [runId, scenarioId, finish]);

  // S1L replays whichever recording is on file; if the model resisted, say so instead of staging a catch.
  const [resisted, setResisted] = useState(false);
  useEffect(() => {
    if (scenarioId === "s1l") api.meta().then((m) => setResisted(m.live_recording?.followed_injection === "False"), () => {});
  }, [scenarioId]);

  // The player: one cursor drives both halves.
  useEffect(() => {
    if (!playing || cursor >= steps.length) return;
    const t = setTimeout(() => setCursor((c) => c + 1), (cursor === 0 ? 400 : STEP_MS) / speed);
    return () => clearTimeout(t);
  }, [playing, cursor, steps.length, speed]);

  const next = () => {
    setPlaying(false);
    setCursor((c) => Math.min(c + 1, steps.length));
  };
  const restart = () => {
    setCursor(0);
    setPlaying(true);
  };

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.target as HTMLElement).tagName === "SELECT") return;
      if (e.key === " ") {
        e.preventDefault();
        setPlaying((p) => !p);
      } else if (e.key === "ArrowRight") next();
      else if (e.key.toLowerCase() === "r") restart();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  });

  const current = steps[cursor - 1];
  const atEnd = status === "done" && cursor >= steps.length;
  const name = result?.name ?? scenarioId.toUpperCase();

  return (
    <div className="flex min-h-screen flex-col lg:h-screen">
      <Header />
      <div className="flex flex-wrap items-center gap-x-6 gap-y-2 border-b border-line px-6 py-3">
        <div className="min-w-0">
          <Label>
            two views · {scenarioId ? scenarioId.toUpperCase() : "run"} · {runId === "new" ? "starting" : runId}
          </Label>
          <h1 className="font-display text-[28px] leading-tight font-semibold">{name}</h1>
          {resisted && (
            <p className="text-[15px] text-amber italic">
              This recording is a real Gemini run in which the model ignored the hidden instruction.
            </p>
          )}
        </div>
        <div className="flex flex-wrap items-center gap-2 lg:ml-auto">
          <span className="mr-3 font-mono text-[13px] text-bone-dim">
            {status === "done" ? (launched.current ? "live run · complete" : "replay") : "● live"} · step{" "}
            {cursor} / {steps.length}
            {status !== "done" && steps.length ? "+" : ""}
          </span>
          <Button onClick={() => setPlaying((p) => !p)} aria-keyshortcuts="Space" className="w-[92px]">
            {playing ? "pause" : "play"}
          </Button>
          <Button onClick={next} disabled={cursor >= steps.length} aria-keyshortcuts="ArrowRight">
            next step
          </Button>
          <Button onClick={restart} aria-keyshortcuts="R">
            restart
          </Button>
          <label className="ml-2 flex items-center gap-2">
            <Label>speed</Label>
            <select
              value={speed}
              onChange={(e) => setSpeed(Number(e.target.value) as (typeof SPEEDS)[number])}
              className="rounded-[2px] border border-line-hi bg-ink px-2 py-1 font-mono text-[13px] text-bone"
            >
              {SPEEDS.map((s) => (
                <option key={s} value={s}>
                  {s}×
                </option>
              ))}
            </select>
          </label>
        </div>
      </div>

      {error && <p className="border-b border-oxblood bg-oxblood/20 px-6 py-2 font-mono text-[13px] text-parch">{error}</p>}
      {status === "missing" ? (
        <p className="p-10 text-bone-dim italic">
          This run isn’t on file — the server may have restarted. Launch it again from the console.
        </p>
      ) : (
        <main className="grid flex-1 grid-cols-1 gap-6 px-6 py-4 lg:min-h-0 lg:grid-cols-2">
          <section className="flex min-h-[420px] flex-col lg:min-h-0">
            <ViewTitle title="What the agent sees" plain="Its own terminal. Every call goes through; every reply looks like success." />
            <div className="min-h-0 flex-1">
              <AgentTerminal steps={steps} cursor={cursor} />
            </div>
          </section>
          <section className="flex min-h-[420px] flex-col lg:min-h-0">
            <ViewTitle title="What Doppel sees" plain="The same call, weighed by nine witnesses against the role." />
            <div className="min-h-0 flex-1">
              <DefenderPanel current={current} />
            </div>
          </section>
        </main>
      )}
      {atEnd && result && (
        <FinalBanner scenarioId={result.id} steps={steps} result={result} stolen={stolen} resisted={resisted} />
      )}
    </div>
  );
}
