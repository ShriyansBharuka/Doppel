import { useCallback, useEffect, useState, type ReactNode } from "react";
import { motion } from "framer-motion";
import {
  CartesianGrid,
  Line,
  LineChart,
  ReferenceArea,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { api, type S5Day } from "../api";
import { useStream } from "../useStream";
import { Header } from "../components/Header";
import { Button, Label, SectionHead } from "../components/ui";

// Validated with the dataviz palette script against the #13100c chart surface (dark): all checks pass.
const CUSUM = "#b98236";
const EWMA = "#4b8ad6";
const INK = "var(--color-bone-dim)";
const ALARM = "var(--color-oxblood-hi)";

/** Runs of ≥ 3 consecutive alarmed days — the "sustained" rule S5 is judged by. */
function sustainedRuns(series: S5Day[]): [number, number][] {
  const runs: [number, number][] = [];
  let start: number | null = null;
  series.forEach((d, i) => {
    if (d.cusum_alarm && start === null) start = d.day;
    const ends = !d.cusum_alarm || i === series.length - 1;
    if (start !== null && ends) {
      const end = d.cusum_alarm ? d.day : series[i - 1].day;
      if (end - start + 1 >= 3) runs.push([start, end]);
      start = null;
    }
  });
  return runs;
}

const axis = { stroke: "var(--color-line-hi)", tick: { fill: INK, fontSize: 12, fontFamily: "JetBrains Mono" } };

function DayTooltip({ active, payload }: { active?: boolean; payload?: { payload: S5Day }[] }) {
  const d = payload?.[0]?.payload;
  if (!active || !d) return null;
  return (
    <div className="rounded-[2px] border border-line-hi bg-ink/95 px-3 py-2 font-mono text-[12px] leading-relaxed text-bone">
      <div className="text-amber">day {d.day}</div>
      <div>divergence {d.divergence.toFixed(4)}</div>
      <div>
        CUSUM {d.cusum.toFixed(4)} / h {d.h.toFixed(4)} {d.cusum_alarm && <b className="text-oxblood-hi">· alarm</b>}
      </div>
      <div>
        EWMA {d.ewma_score.toFixed(4)} {d.ewma_alarm && <b className="text-oxblood-hi">· over threshold</b>}
      </div>
      <div className="text-bone-dim">busiest single call: risk {d.max_event_risk_without_d6}</div>
    </div>
  );
}

function ChartCard({ title, plain, children }: { title: string; plain: string; children: ReactNode }) {
  return (
    <section className="panel rounded-[3px] p-5">
      <h2 className="font-display text-[24px] leading-tight font-semibold">{title}</h2>
      <p className="mb-3 text-[15px] text-bone-dim italic">{plain}</p>
      {children}
    </section>
  );
}

export default function Drift() {
  const [series, setSeries] = useState<S5Day[] | null>(null);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => api.s5Series().then(setSeries, (e) => setError(e.message)), []);
  useEffect(() => {
    load();
  }, [load]);

  useStream((m) => {
    if (m.type === "scenario_done" && m.data.scenario_id === "s5") {
      setRunning(false);
      load();
    }
  });

  const runS5 = () => {
    setRunning(true);
    setError(null);
    api.runScenario("s5", { reset: true, step_delay_ms: 0 }).catch((e) => {
      setRunning(false);
      setError(e.message);
    });
  };

  const alarmDay = series?.find((d) => d.cusum_alarm)?.day;
  const runs = series ? sustainedRuns(series) : [];
  const h = series?.[0]?.h;
  const ewmaThreshold = series?.[0]?.ewma_threshold;
  const busiest = series ? Math.max(...series.map((d) => d.max_event_risk_without_d6)) : 0;
  const ewmaAlarmDays = series?.filter((d) => d.ewma_alarm).length ?? 0;

  return (
    <div className="min-h-screen">
      <Header />
      <main className="mx-auto max-w-[1300px] px-4 py-8 lg:px-8">
        <div className="flex flex-wrap items-end justify-between gap-4">
          <SectionHead
            kicker="slow drift · scenario s5"
            title="Drift over thirty days"
            plain="A procurement agent’s habits shift 3% a day, every call inside its contract."
          />
          <Button onClick={runS5} disabled={running}>
            {running ? "running s5… about a minute" : series?.length ? "re-run s5" : "run s5"}
          </Button>
        </div>

        {error && <p className="mt-4 font-mono text-[13px] text-oxblood-hi">{error}</p>}
        {series && series.length === 0 && !running && (
          <p className="mt-10 max-w-xl text-[18px] text-bone-dim italic">
            No drift series on file yet. Run S5 to simulate 20 training days and 30 drifting days through the real gateway.
          </p>
        )}

        {series && series.length > 0 && (
          <>
            <div className="mt-6 mb-4 flex flex-wrap items-center gap-x-8 gap-y-3">
              <p className="font-display text-[30px] leading-tight font-semibold">
                Each day looks normal on its own. The running total doesn’t.
              </p>
              {alarmDay && (
                <motion.span
                  initial={{ opacity: 0, scale: 1.6, rotate: 0 }}
                  animate={{ opacity: 0.95, scale: 1, rotate: -3 }}
                  transition={{ delay: 0.6, type: "spring", stiffness: 240, damping: 15 }}
                  className="rounded-[3px] border-[3px] border-double border-oxblood-hi px-3 font-display text-[28px] font-bold tracking-[0.1em] text-oxblood-hi"
                >
                  CAUGHT ON DAY {alarmDay}
                </motion.span>
              )}
            </div>
            <p className="mt-1 text-[15px] text-bone-dim">
              The busiest single call in all thirty days scored risk {busiest} — {busiest < 30 ? "below WATCH, so no per-call alarm ever fired" : "the per-call detectors also reacted"}.
              Observed alarm day ≈ 13–22 across seeds; this run is one seed.
            </p>

            <div className="mt-6 grid gap-6">
              <ChartCard
                title="CUSUM against the frozen anchor"
                plain={`Running total of how far each day drifts from the frozen baseline. Alarm when it crosses h${h ? ` = ${h.toFixed(3)}` : ""}.`}
              >
                <ResponsiveContainer width="100%" height={280}>
                  <LineChart data={series} syncId="drift" margin={{ top: 16, right: 24, bottom: 4, left: 4 }}>
                    <CartesianGrid stroke="var(--color-line)" vertical={false} />
                    {runs.map(([a, b]) => (
                      <ReferenceArea key={a} x1={a} x2={b} fill={ALARM} fillOpacity={0.14} label={{ value: "sustained alarm", fill: INK, fontSize: 12, position: "insideTop" }} />
                    ))}
                    <XAxis dataKey="day" {...axis} tickLine={false} />
                    <YAxis {...axis} tickLine={false} width={56} tickFormatter={(v: number) => v.toFixed(2)} />
                    {h !== undefined && (
                      <ReferenceLine y={h} stroke="var(--color-bone)" strokeDasharray="6 5" label={{ value: "h", fill: "var(--color-bone)", position: "right", fontSize: 13 }} />
                    )}
                    {alarmDay && <ReferenceLine x={alarmDay} stroke={ALARM} strokeWidth={2} />}
                    <Tooltip content={<DayTooltip />} cursor={{ stroke: "var(--color-bone-dim)", strokeWidth: 1 }} />
                    <Line type="linear" dataKey="cusum" stroke={CUSUM} strokeWidth={2} dot={false} activeDot={{ r: 5 }} isAnimationActive={false} />
                  </LineChart>
                </ResponsiveContainer>
              </ChartCard>

              <ChartCard
                title="EWMA, the rolling baseline"
                plain="The usual approach: compare each day to a moving average. It drifts along with the agent, so it never sounds a sustained alarm."
              >
                <ResponsiveContainer width="100%" height={240}>
                  <LineChart data={series} syncId="drift" margin={{ top: 16, right: 24, bottom: 4, left: 4 }}>
                    <CartesianGrid stroke="var(--color-line)" vertical={false} />
                    <XAxis dataKey="day" {...axis} tickLine={false} label={{ value: "simulated day", fill: INK, fontSize: 12, position: "insideBottomRight", offset: -2 }} />
                    <YAxis {...axis} tickLine={false} width={56} tickFormatter={(v: number) => v.toFixed(3)} />
                    {ewmaThreshold !== undefined && (
                      <ReferenceLine y={ewmaThreshold} stroke="var(--color-bone)" strokeDasharray="6 5" label={{ value: "threshold", fill: "var(--color-bone)", position: "right", fontSize: 13 }} />
                    )}
                    <Tooltip content={<DayTooltip />} cursor={{ stroke: "var(--color-bone-dim)", strokeWidth: 1 }} />
                    <Line
                      type="linear"
                      dataKey="ewma_score"
                      stroke={EWMA}
                      strokeWidth={2}
                      isAnimationActive={false}
                      activeDot={{ r: 5 }}
                      dot={(p: { cx?: number; cy?: number; payload?: S5Day; index?: number }) =>
                        p.payload?.ewma_alarm ? (
                          <circle key={p.index} cx={p.cx} cy={p.cy} r={5} fill={ALARM} stroke="var(--color-desk)" strokeWidth={2} />
                        ) : (
                          <g key={p.index} />
                        )
                      }
                    />
                  </LineChart>
                </ResponsiveContainer>
                {ewmaThreshold === undefined && (
                  <p className="mt-1 text-[13px] text-bone-dim italic">
                    The backend doesn’t report the EWMA threshold yet, so days over it are marked with a red dot instead of a line
                    {ewmaAlarmDays ? ` (${ewmaAlarmDays} in this run)` : " — none in this run"}.
                  </p>
                )}
              </ChartCard>
            </div>

            <details className="mt-6 text-bone-dim">
              <summary className="cursor-pointer">
                <Label>the numbers, day by day</Label>
              </summary>
              <table className="mt-3 w-full font-mono text-[12px]">
                <thead className="text-left text-bone">
                  <tr>
                    {["day", "divergence", "CUSUM", "h", "CUSUM alarm", "EWMA", "EWMA alarm", "busiest call risk"].map((c) => (
                      <th key={c} className="border-b border-line py-1 pr-4 font-normal">
                        {c}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {series.map((d) => (
                    <tr key={d.day} className="border-b border-line/50">
                      <td className="py-0.5 pr-4">{d.day}</td>
                      <td className="pr-4">{d.divergence.toFixed(4)}</td>
                      <td className="pr-4">{d.cusum.toFixed(4)}</td>
                      <td className="pr-4">{d.h.toFixed(4)}</td>
                      <td className={`pr-4 ${d.cusum_alarm ? "text-oxblood-hi" : ""}`}>{d.cusum_alarm ? "yes" : "—"}</td>
                      <td className="pr-4">{d.ewma_score.toFixed(4)}</td>
                      <td className={`pr-4 ${d.ewma_alarm ? "text-oxblood-hi" : ""}`}>{d.ewma_alarm ? "yes" : "—"}</td>
                      <td>{d.max_event_risk_without_d6}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </details>
          </>
        )}
      </main>
    </div>
  );
}
