import type { ReactNode } from "react";
import { motion } from "framer-motion";
import { clockTime, maskWatermarks, type Contribution, type DoppelEvent, type Tier } from "../../api";
import { TAGS, WITNESSES, witnessLabel } from "../../vocab";

export function CaseSection({ kicker, title, plain, children }: { kicker: string; title: string; plain: string; children: ReactNode }) {
  return (
    <section className="border-t border-parch-edge/60 pt-4">
      <span className="label !text-sepia/60">{kicker}</span>
      <h2 className="font-display text-[26px] leading-tight font-semibold">{title}</h2>
      <p className="mb-3 text-[15px] text-sepia/70 italic">{plain}</p>
      {children}
    </section>
  );
}

export function RiskDial({ risk }: { risk: number }) {
  const r = 52;
  const len = 2 * Math.PI * r;
  return (
    <svg viewBox="0 0 128 128" className="h-[132px] w-[132px] shrink-0" role="img" aria-label={`Risk ${risk} of 100`}>
      <circle cx="64" cy="64" r={r} fill="none" stroke="rgba(58,42,26,0.15)" strokeWidth="10" />
      <motion.circle
        cx="64"
        cy="64"
        r={r}
        fill="none"
        stroke="var(--color-oxblood)"
        strokeWidth="10"
        strokeDasharray={len}
        initial={{ strokeDashoffset: len }}
        animate={{ strokeDashoffset: len * (1 - risk / 100) }}
        transition={{ duration: 1.4, ease: "easeOut" }}
        transform="rotate(-90 64 64)"
      />
      <text x="64" y="70" textAnchor="middle" fontFamily="JetBrains Mono, monospace" fontSize="34" fontWeight="500" fill="var(--color-oxblood)">
        {risk}
      </text>
      <text x="64" y="90" textAnchor="middle" fontFamily="Cormorant SC, serif" fontSize="12" letterSpacing="2" fill="var(--color-sepia)">
        RISK / 100
      </text>
    </svg>
  );
}

export function Stamp({ tier }: { tier: Tier }) {
  if (tier === "ALLOW") return null;
  return (
    <motion.span
      initial={{ opacity: 0, scale: 1.6 }}
      animate={{ opacity: 0.85, scale: 1 }}
      transition={{ delay: 0.5, type: "spring", stiffness: 240, damping: 15 }}
      className="pointer-events-none absolute top-3 right-3 rotate-[-11deg] rounded-[4px] border-[4px] border-double border-oxblood px-2 py-0.5 font-display text-[22px] font-bold tracking-[0.14em] text-oxblood mix-blend-multiply sm:top-8 sm:right-10 sm:px-4 sm:py-1 sm:text-[40px]"
    >
      {tier === "ISOLATE" ? "ISOLATED" : tier}
    </motion.span>
  );
}

export function WitnessBars({ contributions }: { contributions: Contribution[] }) {
  const sorted = [...contributions].sort((a, b) => b.share_pct - a.share_pct);
  return (
    <ul className="flex flex-col gap-3">
      {sorted.map((c, i) => (
        <li key={c.detector}>
          <div className="flex items-baseline justify-between gap-3">
            <span className="text-[17px] font-semibold">
              <span className="font-mono text-[12px] font-normal text-sepia/60">
                {WITNESSES.find((w) => w.name === c.detector)?.id}{" "}
              </span>
              {witnessLabel(c.detector)}
            </span>
            <span className="font-mono text-[13px] text-sepia/80">
              {c.share_pct.toFixed(1)}% · score {c.score.toFixed(2)}
            </span>
          </div>
          <div className="mt-1 h-2.5 rounded-[1px] bg-sepia/10">
            <motion.div
              className="h-full rounded-[1px] bg-oxblood"
              initial={{ width: 0 }}
              animate={{ width: `${c.share_pct}%` }}
              transition={{ delay: 0.3 + i * 0.12, duration: 0.9, ease: "easeOut" }}
            />
          </div>
          {c.evidence.map((e) => (
            <p key={e} className="mt-1 text-[15px] leading-snug italic">
              {maskWatermarks(e)}
            </p>
          ))}
        </li>
      ))}
    </ul>
  );
}

export function TagChips({ tags }: { tags: string[] }) {
  return (
    <ul className="flex flex-wrap gap-2">
      {tags.map((t) => (
        <li key={t} className="group relative">
          <span
            tabIndex={0}
            aria-describedby={`tag-${t}`}
            className="inline-block cursor-help rounded-[2px] border border-sepia/50 px-2 py-0.5 font-mono text-[12px] outline-none focus:border-oxblood"
          >
            {t}
          </span>
          <span
            id={`tag-${t}`}
            role="tooltip"
            className="pointer-events-none absolute bottom-full left-0 z-10 mb-2 hidden w-72 max-w-[70vw] rounded-[2px] bg-ink px-3 py-2 text-[14px] leading-snug text-bone shadow-lg group-hover:block group-focus-within:block"
          >
            {TAGS[t] ?? "A standard reference for this kind of agent attack."}
          </span>
        </li>
      ))}
    </ul>
  );
}

export function ActionsTimeline({ actions }: { actions: string[] }) {
  return (
    <ol className="relative ml-2 border-l-2 border-oxblood/40 pl-5">
      {actions.map((a) => (
        <li key={a} className="relative pb-2 text-[16px] leading-snug">
          <span className="absolute top-1.5 -left-[27px] h-3 w-3 rounded-full border-2 border-parch bg-oxblood" />
          {a}
        </li>
      ))}
    </ol>
  );
}

const DECISION_WORD: Record<string, string> = { allow: "allowed", hold: "held", sinkhole: "sinkholed", decoy: "decoy", block: "blocked" };

export function EventTimeline({ events }: { events: DoppelEvent[] }) {
  return (
    <ol className="font-mono text-[12.5px]">
      {events.map((e) => (
        <li key={e.event_id} className="grid grid-cols-[62px_minmax(0,1fr)_70px_34px] gap-2 border-b border-parch-edge/40 py-1">
          <span className="text-sepia/60">{clockTime(e.timestamp)}</span>
          <span className="truncate" title={e.target ?? undefined}>
            {e.tool}
            {e.target && <span className="text-sepia/60"> → {e.target}</span>}
          </span>
          <span className={e.decision === "allow" ? "text-sepia/60" : "font-medium text-oxblood"}>
            {DECISION_WORD[e.decision] ?? e.decision}
          </span>
          <span className="text-right">{e.risk}</span>
        </li>
      ))}
    </ol>
  );
}
