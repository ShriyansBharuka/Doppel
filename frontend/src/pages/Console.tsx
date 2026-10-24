import { useCallback, useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  allowedHosts,
  api,
  stolenBytes,
  type Alert,
  type AgentDetail,
  type DoppelEvent,
  type ScenarioMeta,
  type StreamMessage,
} from "../api";
import { useStream } from "../useStream";
import { Header } from "../components/Header";
import { Button, Label } from "../components/ui";
import { Subjects } from "../components/console/Subjects";
import { Feed } from "../components/console/Feed";
import { CaseFiles } from "../components/console/CaseFiles";
import { Launcher } from "../components/console/Launcher";

const FEED_CAP = 150; // S5 streams thousands of events; the feed is a window, not an archive

export default function Console() {
  const [agents, setAgents] = useState<AgentDetail[]>([]);
  const [liveRisk, setLiveRisk] = useState<Record<string, number>>({});
  const [feed, setFeed] = useState<DoppelEvent[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [stolen, setStolen] = useState(0);
  const [scenarios, setScenarios] = useState<ScenarioMeta[]>([]);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();

  const hosts = useRef<Promise<Set<string>> | null>(null);
  const refreshStolen = useCallback(() => {
    hosts.current ??= allowedHosts();
    Promise.all([api.worldState(), hosts.current]).then(
      ([w, allowed]) => setStolen(stolenBytes(w.egress_log, allowed)),
      () => {},
    );
  }, []);

  const load = useCallback(async () => {
    try {
      const [list, events, alertList] = await Promise.all([api.agents(), api.events(), api.alerts()]);
      setAgents(await Promise.all(list.map((a) => api.agent(a.agent_id))));
      setFeed(events.slice(-FEED_CAP).reverse());
      setAlerts([...alertList].reverse());
      refreshStolen();
      setError(null);
    } catch (e) {
      setError(`Couldn't load the console: ${(e as Error).message}`);
    }
  }, [refreshStolen]);

  useEffect(() => {
    load();
    api.scenarios().then(setScenarios, (e) => setError(`Couldn't load scenarios: ${e.message}`));
  }, [load]);

  // Batch stream messages per animation frame so a burst (S5) is one render, not thousands.
  const queue = useRef<StreamMessage[]>([]);
  const frame = useRef(0);
  const flush = useCallback(() => {
    frame.current = 0;
    const msgs = queue.current;
    queue.current = [];
    const events = msgs.flatMap((m) => (m.type === "event" ? [m.data] : []));
    const incoming = msgs.flatMap((m) => (m.type === "alert" ? [m.data] : []));

    if (events.length) {
      setFeed((f) => [...events.reverse(), ...f].slice(0, FEED_CAP));
      if (events.some((e) => e.action_type === "egress")) refreshStolen();
    }
    if (events.length || incoming.length) {
      setLiveRisk((r) => {
        const next = { ...r };
        for (const x of [...events, ...incoming]) next[x.agent_id] = Math.max(next[x.agent_id] ?? 0, x.risk);
        return next;
      });
    }
    if (incoming.length) {
      setAlerts((list) => {
        const next = [...list];
        for (const a of incoming) {
          const i = next.findIndex((x) => x.alert_id === a.alert_id);
          if (i >= 0) next[i] = a;
          else next.unshift(a);
        }
        return next;
      });
    }
  }, [refreshStolen]);

  const stream = useStream((msg) => {
    queue.current.push(msg);
    if (!frame.current) frame.current = requestAnimationFrame(flush);
  });

  const reset = async () => {
    try {
      await api.reset();
      setLiveRisk({});
      await load();
    } catch (e) {
      setError(`Reset failed: ${(e as Error).message}`);
    }
  };

  return (
    <div className="flex min-h-screen flex-col lg:h-screen">
      <Header
        right={
          <>
            <div
              className="text-right"
              title="Bytes that reached a host no agent is allowed to talk to. Sinkholed payloads never left, and traffic to approved hosts isn't theft."
            >
              <span className={`font-mono text-[20px] ${stolen ? "text-shrink" : "text-amber"}`}>
                {stolen.toLocaleString()} bytes
              </span>
              <Label className="block !text-[12px]">stolen</Label>
            </div>
            <span className="flex items-center gap-2 font-mono text-[12px] text-bone-dim">
              <span
                className={`h-2 w-2 rounded-full ${stream === "open" ? "bg-amber candle" : "bg-oxblood-hi"}`}
                aria-hidden
              />
              {stream === "open" ? "stream live" : "reconnecting…"}
            </span>
            <Button onClick={reset}>reset world</Button>
          </>
        }
      />
      <Launcher scenarios={scenarios} onRun={(id) => navigate(`/scenario/new?s=${id}`)} />
      {error && (
        <p role="alert" className="border-b border-oxblood bg-oxblood/20 px-6 py-2 font-mono text-[13px] text-parch">
          {error}
        </p>
      )}
      <main className="grid flex-1 grid-cols-1 gap-8 p-4 lg:min-h-0 lg:grid-cols-[300px_minmax(0,1fr)_350px] lg:gap-5 lg:overflow-hidden lg:px-6">
        <Subjects agents={agents} liveRisk={liveRisk} />
        <Feed events={feed} />
        <CaseFiles alerts={alerts} />
      </main>
    </div>
  );
}
