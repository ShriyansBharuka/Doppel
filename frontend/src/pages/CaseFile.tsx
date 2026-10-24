import { useCallback, useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import {
  api,
  ApiError,
  clockTime,
  type AgentDetail,
  type Alert,
  type Approval,
  type Contract,
  type DoppelEvent,
  type Session,
} from "../api";
import { useStream } from "../useStream";
import { Header } from "../components/Header";
import { HumanControls } from "../components/case/HumanControls";
import { RootCause } from "../components/case/RootCause";
import {
  ActionsTimeline,
  CaseSection,
  EventTimeline,
  RiskDial,
  Stamp,
  TagChips,
  WitnessBars,
} from "../components/case/Sections";
import { CLAUSES } from "../vocab";

interface CaseData {
  alert: Alert;
  agent: AgentDetail | null;
  session: Session | null;
  events: DoppelEvent[];
  approvals: Approval[];
  captures: number;
  contract: Contract | null;
  instruction?: string;
}

async function loadCase(alertId: string): Promise<CaseData> {
  const alert = await api.alert(alertId);
  const sid = alert.session_id;
  const [agent, session, events, approvals, sinkhole, world, contract] = await Promise.all([
    api.agent(alert.agent_id).catch(() => null),
    api.session(sid).catch(() => null),
    api.events(sid).catch(() => []),
    api.approvals("pending", sid).catch(() => []),
    api.sinkhole().catch(() => []),
    api.worldState().catch(() => null),
    api.contract(alert.agent_id).catch(() => null),
  ]);
  const instruction = world?.delegations.find(
    (d) => d.from_session === session?.parent_session_id && d.to_agent === alert.agent_id,
  )?.instruction;
  return {
    alert,
    agent,
    session,
    events,
    approvals,
    captures: sinkhole.filter((c) => c.session_id === sid).length,
    contract,
    instruction,
  };
}

function ClauseBroken({ clause, contract }: { clause: string | null; contract: Contract | null }) {
  if (!clause)
    return (
      <p className="text-[16px] italic">
        None. Every call stayed inside the role’s written permissions — the drift was caught on behaviour, not on a
        broken rule.
      </p>
    );
  const value = contract?.[clause as keyof Contract];
  return (
    <div>
      <p className="text-[18px] font-semibold">{CLAUSES[clause] ?? clause}</p>
      {value !== undefined ? (
        <blockquote className="mt-1 border-l-2 border-oxblood pl-3 font-mono text-[13px]">
          {clause}: {Array.isArray(value) ? `[${value.join(", ")}]` : String(value)}
          <span className="block text-sepia/60">
            signed contract v{contract?.version} · owner {contract?.owner}
          </span>
        </blockquote>
      ) : (
        <p className="font-mono text-[13px] text-sepia/70">{clause} · signed role contract</p>
      )}
    </div>
  );
}

export default function CaseFile() {
  const { alertId = "" } = useParams();
  const [data, setData] = useState<CaseData | null>(null);
  const [missing, setMissing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const reload = useCallback(() => {
    loadCase(alertId).then(setData, (e) => {
      if (e instanceof ApiError && e.status === 404) setMissing(true);
      else setError(e.message);
    });
  }, [alertId]);

  useEffect(reload, [reload]);

  useStream((m) => {
    if (!data) return;
    if (m.type === "alert" && m.data.alert_id === alertId) reload();
    if (m.type === "approval" && m.data.session_id === data.alert.session_id) reload();
  });

  if (missing)
    return (
      <div className="min-h-screen">
        <Header />
        <p className="mx-auto max-w-2xl px-6 py-20 text-[19px] text-bone-dim italic">
          Case file {alertId} isn’t in the drawer. The world was probably reset since it was filed — run the scenario again
          to reopen it.
        </p>
      </div>
    );

  if (!data)
    return (
      <div className="min-h-screen">
        <Header />
        <p className="px-6 py-20 text-center text-bone-dim italic">{error ?? "Pulling the file…"}</p>
      </div>
    );

  const { alert, agent, session, events } = data;
  const receipt = alert.receipt;

  return (
    <div className="min-h-screen">
      <Header />
      <main className="mx-auto grid max-w-[1560px] grid-cols-[minmax(0,1fr)] gap-8 px-4 py-8 lg:grid-cols-[minmax(0,1fr)_300px] lg:px-8">
        <article className="parchment relative rounded-[2px] px-6 py-8 sm:px-10">
          <Stamp tier={alert.tier} />
          <div className="flex flex-wrap items-baseline gap-x-6">
            <span className="label !text-sepia/70">case / {alert.alert_id}</span>
            <span className="font-mono text-[12px] text-sepia/60">
              filed {clockTime(alert.created_at)} · {alert.status}
            </span>
          </div>

          <header className="mt-4 flex flex-wrap items-center gap-8 pr-0 lg:pr-56">
            <RiskDial risk={alert.risk} />
            <div className="min-w-0 flex-1">
              <span className="label !text-sepia/60">subject</span>
              <p className="text-[18px]">
                <b className="font-semibold">{agent?.role ?? alert.agent_id}</b>{" "}
                <span className="font-mono text-[13px] text-sepia/70">{alert.agent_id}</span>
              </p>
              <h1 className="mt-1 font-display text-[28px] leading-[1.08] font-bold [overflow-wrap:anywhere] sm:text-[38px]">
                {receipt?.headline_short || alert.headline}
              </h1>
            </div>
          </header>

          {receipt ? (
            <div className="mt-8 grid grid-cols-[minmax(0,1fr)] gap-x-10 gap-y-6 xl:grid-cols-[minmax(0,1.15fr)_minmax(0,1fr)]">
              <div className="flex flex-col gap-6">
                <CaseSection kicker="testimony" title="Witnesses" plain="How much each detector contributed to the risk, and what it saw.">
                  <WitnessBars contributions={receipt.contributions} />
                </CaseSection>
                <CaseSection kicker="where it started" title="Root cause" plain="The last untrusted input the agent read before it drifted.">
                  <RootCause receipt={receipt} session={session} instruction={data.instruction} />
                </CaseSection>
              </div>
              <div className="flex flex-col gap-6">
                <CaseSection kicker="the contract" title="Clause broken" plain="Which line of the signed role contract this crossed.">
                  <ClauseBroken clause={receipt.contract_clause} contract={data.contract} />
                </CaseSection>
                <CaseSection kicker="response" title="Actions taken" plain="What Doppel did, in order. All of it can be undone.">
                  <ActionsTimeline actions={receipt.actions_taken} />
                </CaseSection>
                <CaseSection kicker="the record" title="Session timeline" plain="Every call this session made, as the gateway logged it.">
                  <EventTimeline events={events} />
                </CaseSection>
                <CaseSection kicker="references" title="Threat tags" plain="Where this sits in the OWASP agentic top 10 and MITRE ATLAS. Hover for meaning.">
                  <TagChips tags={receipt.tags} />
                </CaseSection>
              </div>
            </div>
          ) : (
            <p className="mt-8 italic">The Drift Receipt for this alert hasn’t been written yet.</p>
          )}
        </article>

        <HumanControls
          alert={alert}
          session={session}
          approvals={data.approvals}
          captures={data.captures}
          rootSource={receipt?.root_cause?.source ?? null}
          onChange={reload}
        />
      </main>
    </div>
  );
}
