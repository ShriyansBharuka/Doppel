import { AnimatePresence, motion } from "framer-motion";
import { maskWatermarks, topEvidence, type Tier } from "../../api";
import { WITNESSES } from "../../vocab";
import { Label, TIER_COLOR } from "../ui";
import type { PairedStep } from "./AgentTerminal";

const LADDER: { tier: Tier; floor: number; plain: string }[] = [
  { tier: "ISOLATE", floor: 80, plain: "mirror world: real access cut, traps stay open" },
  { tier: "SHRINK", floor: 60, plain: "write, egress and delegation quietly removed" },
  { tier: "WATCH", floor: 30, plain: "risky calls held for a human" },
  { tier: "ALLOW", floor: 0, plain: "business as usual" },
];
const RANK: Record<Tier, number> = { ALLOW: 0, WATCH: 1, SHRINK: 2, ISOLATE: 3 };

const DECISION: Record<string, { word: string; plain: string; cls: string }> = {
  allow: { word: "allow", plain: "executed for real", cls: "text-bone" },
  hold: { word: "hold", plain: "parked until a human approves", cls: "text-amber" },
  sinkhole: { word: "sinkhole", plain: "fake success — the payload went to the evidence locker", cls: "text-oxblood-hi" },
  decoy: { word: "decoy", plain: "served a watermarked fake instead of the real data", cls: "text-amber" },
  block: { word: "block", plain: "refused at the gateway", cls: "text-shrink" },
};
const TRAP_OPEN = { word: "allow", plain: "on purpose — it’s a decoy, so the trap stays open", cls: "text-amber" };

function RiskMeter({ risk, tier }: { risk: number; tier: Tier }) {
  return (
    <div className="flex h-full flex-col items-center gap-2">
      <Label>risk</Label>
      <div className="relative w-14 flex-1">
        <div className="absolute inset-0 overflow-hidden rounded-[2px] border border-line-hi bg-ink">
          <motion.div
            className="absolute inset-x-0 bottom-0"
            animate={{ height: `${risk}%`, backgroundColor: TIER_COLOR[tier] }}
            transition={{ duration: 1.1, ease: [0.3, 0.7, 0.2, 1] }}
          />
        </div>
        {[30, 60, 80].map((t) => (
          <div key={t} className="absolute inset-x-0 border-t border-dashed border-bone-dim/50" style={{ bottom: `${t}%` }}>
            <span className="absolute -top-2.5 right-full mr-1.5 font-mono text-[11px] text-bone-dim">{t}</span>
          </div>
        ))}
      </div>
      <motion.span key={risk} initial={{ scale: 1.25 }} animate={{ scale: 1 }} className="font-mono text-[34px] leading-none text-bone 2xl:text-[44px]">
        {risk}
      </motion.span>
    </div>
  );
}

function TierLadder({ tier }: { tier: Tier }) {
  return (
    <div>
      {/* The stamp gets its own row so it never sits on top of the ISOLATE rung's text. */}
      <div className="mb-1.5 flex h-10 items-center justify-between 2xl:h-14">
        <Label>response tier</Label>
        <AnimatePresence>
          {tier === "ISOLATE" && (
            <motion.span
              initial={{ opacity: 0, scale: 1.8, rotate: 0 }}
              animate={{ opacity: 0.95, scale: 1, rotate: -2 }}
              transition={{ type: "spring", stiffness: 260, damping: 16 }}
              className="pointer-events-none rounded-[3px] border-[3px] border-oxblood-hi px-2 font-display text-[20px] leading-tight font-bold tracking-[0.12em] text-oxblood-hi 2xl:text-[24px]"
            >
              MIRROR WORLD
            </motion.span>
          )}
        </AnimatePresence>
      </div>
      <ol className="flex flex-col gap-1.5">
        {LADDER.map((r) => {
          const lit = RANK[tier] >= RANK[r.tier];
          const current = tier === r.tier;
          return (
            <li
              key={r.tier}
              className={`flex items-baseline gap-3 rounded-[2px] border px-3 py-1.5 transition-all duration-700 2xl:py-2.5 ${
                current ? "border-current" : lit ? "border-line-hi" : "border-line opacity-45"
              } ${current && r.tier === "ISOLATE" ? "pulse-isolate" : ""}`}
              style={{ color: lit ? TIER_COLOR[r.tier] : undefined, background: current ? "rgba(0,0,0,0.35)" : undefined }}
            >
              <span className="w-20 font-mono text-[15px] tracking-[0.14em] 2xl:w-24 2xl:text-[18px]">{r.tier}</span>
              <span className="min-w-0 flex-1 truncate text-[14px] text-bone-dim italic 2xl:text-[17px]">{r.plain}</span>
              <span className="font-mono text-[11px] text-bone-dim">≥ {r.floor}</span>
            </li>
          );
        })}
      </ol>
    </div>
  );
}

function Witnesses({ scores }: { scores: Record<string, number> | null }) {
  return (
    <div>
      <div className="mb-2 flex items-baseline gap-3">
        <Label>witnesses</Label>
        <span className="text-[14px] text-bone-dim italic">nine detectors testify on every call</span>
      </div>
      <ul className="grid grid-cols-2 gap-1.5 sm:grid-cols-3 2xl:gap-2">
        {WITNESSES.map((w) => {
          const s = scores?.[w.name] ?? 0;
          return (
            <li
              key={w.id}
              title={w.plain}
              className="flex items-baseline gap-2 rounded-[2px] border px-2.5 py-1 transition-all duration-700 2xl:py-2"
              style={{
                borderColor: s > 0 ? `rgba(201,163,90,${0.35 + s * 0.65})` : "var(--color-line)",
                background: s > 0 ? `rgba(155,42,42,${0.12 + s * 0.4})` : "transparent",
              }}
            >
              <span className={`font-mono text-[12px] 2xl:text-[14px] ${s > 0 ? "text-amber" : "text-bone-dim/70"}`}>{w.id}</span>
              <span className={`min-w-0 flex-1 truncate text-[15px] 2xl:text-[18px] ${s > 0 ? "text-bone" : "text-bone-dim/60"}`}>
                {w.label}
              </span>
              <span className={`font-mono text-[12px] 2xl:text-[14px] ${s > 0 ? "text-parch" : "text-bone-dim/50"}`}>
                {s > 0 ? s.toFixed(2) : "—"}
              </span>
            </li>
          );
        })}
      </ul>
      {!scores && <p className="mt-2 text-[13px] text-bone-dim italic">Witness scores unavailable for this replay.</p>}
    </div>
  );
}

export function DefenderPanel({ current }: { current: PairedStep | undefined }) {
  const dv = current?.step.defender_view;
  const tier = dv?.tier ?? "ALLOW";
  const risk = dv?.session_risk ?? 0;
  const scores = current?.event
    ? Object.fromEntries(current.event.detector_results.map((d) => [d.name, d.score]))
    : current
      ? null
      : {};
  // Reading a decoy is allowed on purpose (SPEC §8): the trap stays open so the attacker shows its next move.
  const baited = dv?.decision === "allow" && (scores?.decoy ?? 0) > 0;
  const d = baited ? TRAP_OPEN : dv ? DECISION[dv.decision] : undefined;

  return (
    <div className="grid h-full grid-cols-[64px_minmax(0,1fr)] gap-4 rounded-[3px] border border-line bg-desk/80 p-4 sm:grid-cols-[96px_minmax(0,1fr)] sm:gap-6 sm:p-5 2xl:grid-cols-[120px_minmax(0,1fr)] 2xl:p-7">
      <RiskMeter risk={risk} tier={tier} />
      <div className="scroll-quiet flex min-h-0 flex-col gap-4 overflow-x-hidden overflow-y-auto 2xl:gap-6">
        <TierLadder tier={tier} />
        <Witnesses scores={scores} />
        <div className="border-t border-line pt-3">
          <Label>decision on this call</Label>
          <AnimatePresence mode="wait">
            <motion.div key={current?.step.step_number ?? 0} initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}>
              {d ? (
                <>
                  <p className={`font-display text-[32px] leading-none font-semibold 2xl:text-[44px] ${d.cls}`}>
                    {d.word} <span className="text-[17px] font-normal text-bone-dim italic 2xl:text-[21px]">— {d.plain}</span>
                  </p>
                  <p className="mt-2 text-[17px] leading-snug text-bone 2xl:mt-3 2xl:text-[22px]">
                    {(current?.event && topEvidence(current.event)) ??
                      maskWatermarks(dv?.top_evidence[0] ?? "No witness objected.")}
                  </p>
                </>
              ) : (
                <p className="mt-1 text-bone-dim italic">Waiting for the first call.</p>
              )}
            </motion.div>
          </AnimatePresence>
        </div>
      </div>
    </div>
  );
}
