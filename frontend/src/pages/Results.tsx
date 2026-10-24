import { useEffect, useState, type ReactNode } from "react";
import { api, loadResults, type Campaign, type EvalResults } from "../api";
import { Header } from "../components/Header";
import { Label, SectionHead } from "../components/ui";

const FAMILY: Record<string, string> = {
  pdf_injection: "Hidden instruction in a document",
  mimicry: "In-contract mimicry (unknown host)",
  stolen_token: "Stolen token replay",
  poisoned_tool: "Poisoned tool definition",
  agent_chain: "Tainted agent-to-agent hand-off",
  slow_drift: "Slow drift over 30 days",
};

function Stat({ value, label, sub }: { value: ReactNode; label: string; sub?: string }) {
  return (
    <div className="panel rounded-[3px] p-5">
      <div className="font-mono text-[40px] leading-none text-amber">{value}</div>
      <Label className="mt-2 block">{label}</Label>
      {sub && <p className="mt-1 text-[14px] text-bone-dim italic">{sub}</p>}
    </div>
  );
}

function EvalTables({ r }: { r: EvalResults }) {
  const fams = Object.entries(r.attacks.families);
  return (
    <>
      <div className="mt-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Stat value={`${r.attacks.overall_detection_rate_pct}%`} label="attacks detected" sub={`${r.attacks.overall_detected} of ${r.attacks.overall_variants_tested} variants`} />
        <Stat value={r.benign.false_alarms_per_100} label="false alarms / 100 benign" sub={`${r.benign.total_benign_sessions} benign sessions`} />
        <Stat value={`${r.attacks.real_bytes_leaked} B`} label="bytes leaked" sub="read from the real egress log" />
        <Stat value={`${r.latency_ms.p50} / ${r.latency_ms.p95}`} label="added latency p50 / p95 (ms)" sub={`${r.latency_ms.samples.toLocaleString()} gateway calls`} />
      </div>

      <div className="mt-8 overflow-x-auto">
        <table className="w-full min-w-[640px] text-left">
          <thead>
            <tr className="border-b border-line-hi">
              {["Attack family", "Variants", "Detection rate", "Median actions to detect", "Bytes leaked"].map((h) => (
                <th key={h} className="py-2 pr-6 font-normal">
                  <Label>{h}</Label>
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="font-mono text-[14px]">
            {fams.map(([k, m]) => (
              <tr key={k} className="border-b border-line">
                <td className="py-2.5 pr-6 font-body text-[17px]">{FAMILY[k] ?? k}</td>
                <td className="pr-6">{m.variants_tested}</td>
                <td className="pr-6 text-amber">{m.detection_rate_pct}%</td>
                <td className="pr-6">
                  {m.median_alarm_day !== undefined
                    ? `day ${m.median_alarm_day} (days, not calls)`
                    : (m.median_actions_to_detect ?? "n/a")}
                </td>
                <td>{m.real_bytes_leaked} B</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}

function CampaignTable({ c }: { c: Campaign }) {
  const resisted = c.runs - c.followed;
  return (
    <table className="mt-3 w-full max-w-2xl text-left">
      <tbody className="font-mono text-[14px]">
        {[
          ["model", c.model],
          ["live runs", c.runs],
          ["followed the hidden instruction", c.followed],
          ["…and were caught by Doppel", `${c.caught_of_followed} of ${c.followed}`],
          ["resisted the instruction", resisted],
          ["false alarms on runs that resisted", `${c.false_alarms_on_resisted} of ${resisted}`],
          ["recorded", c.date.slice(0, 10)],
        ].map(([k, v]) => (
          <tr key={String(k)} className="border-b border-line">
            <td className="py-2 pr-6 font-body text-[17px] text-bone-dim">{k}</td>
            <td className="text-bone">{v}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export default function Results() {
  const [results, setResults] = useState<EvalResults | null | undefined>(undefined);
  const [campaign, setCampaign] = useState<Campaign | null | undefined>(undefined);

  useEffect(() => {
    loadResults().then(setResults, () => setResults(null));
    api.meta().then((m) => setCampaign(m.live_campaign ?? null), () => setCampaign(null));
  }, []);

  return (
    <div className="min-h-screen">
      <Header />
      <main className="mx-auto max-w-[1300px] px-4 py-8 lg:px-8">
        <SectionHead kicker="the verdict" title="Evaluation results" plain="How often Doppel catches each attack, and what it costs." />
        <p className="inline-block rounded-[2px] border border-amber/60 px-3 py-1 font-mono text-[13px] text-amber">
          measured on the Doppel simulator — not a production benchmark
        </p>

        {results === null && (
          <div className="panel mt-8 max-w-2xl rounded-[3px] p-6">
            <Label>status</Label>
            <p className="font-display text-[28px] font-semibold">Evaluation pending</p>
            <p className="mt-1 text-bone-dim">
              The evaluation harness hasn’t been published to this page yet. When it is, this page shows detection rate per
              attack family, false alarms per 100 benign sessions, bytes leaked, and the latency Doppel adds to each call.
            </p>
          </div>
        )}
        {results && <EvalTables r={results} />}

        <section className="mt-12">
          <SectionHead
            kicker="live agent"
            title="Live Gemini campaign"
            plain="A real model given the poisoned quote, run several times. Did it follow the hidden instruction, and did Doppel catch it?"
          />
          {campaign ? (
            <CampaignTable c={campaign} />
          ) : campaign === null ? (
            <p className="text-bone-dim italic">No live campaign has been recorded on this server yet.</p>
          ) : null}
        </section>
      </main>
    </div>
  );
}
