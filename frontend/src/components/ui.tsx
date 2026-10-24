import type { ButtonHTMLAttributes, ReactNode } from "react";
import type { Tier } from "../api";

export function Label({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <span className={`label ${className}`}>{children}</span>;
}

/** Themed heading with the plain-English subtitle judges need ("Subjects" → "the agents we watch"). */
export function SectionHead({ kicker, title, plain }: { kicker: string; title: string; plain: string }) {
  return (
    <header className="mb-3">
      <Label>{kicker}</Label>
      <h2 className="font-display text-[26px] leading-tight font-semibold text-bone">{title}</h2>
      <p className="text-[15px] text-bone-dim italic">{plain}</p>
    </header>
  );
}

const TIER_STYLE: Record<Tier, string> = {
  ALLOW: "border-bone-dim/40 text-bone-dim",
  WATCH: "border-amber/70 text-amber bg-amber/5",
  SHRINK: "border-shrink text-shrink bg-shrink/10",
  ISOLATE: "border-oxblood-hi bg-oxblood text-parch pulse-isolate",
};

export function TierBadge({ tier }: { tier: Tier }) {
  return (
    <span
      className={`inline-block rounded-[2px] border px-1.5 py-px font-mono text-[11px] tracking-[0.12em] ${TIER_STYLE[tier]}`}
    >
      {tier}
    </span>
  );
}

export const TIER_COLOR: Record<Tier, string> = {
  ALLOW: "var(--color-bone-dim)",
  WATCH: "var(--color-amber)",
  SHRINK: "var(--color-shrink)",
  ISOLATE: "var(--color-oxblood-hi)",
};

export function Button({
  variant = "ghost",
  className = "",
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "blood" | "ghost" }) {
  const look =
    variant === "blood"
      ? "bg-oxblood text-parch border-oxblood-hi hover:bg-oxblood-hi"
      : "bg-transparent text-bone border-line-hi hover:border-amber hover:text-amber";
  return (
    <button
      {...props}
      className={`cursor-pointer rounded-[2px] border px-3 py-1.5 font-label text-[15px] font-semibold tracking-[0.14em] lowercase [font-variant:small-caps] transition-colors duration-300 disabled:cursor-not-allowed disabled:opacity-40 ${look} ${className}`}
    />
  );
}

/** Half-dial gauge, 0–100. */
export function RiskGauge({ risk, tier }: { risk: number; tier: Tier }) {
  const r = 26;
  const len = Math.PI * r;
  return (
    <svg viewBox="0 0 64 38" className="h-[38px] w-[64px]" role="img" aria-label={`Risk ${risk} of 100`}>
      <path d="M6 34 A26 26 0 0 1 58 34" fill="none" stroke="var(--color-line-hi)" strokeWidth="4" />
      <path
        d="M6 34 A26 26 0 0 1 58 34"
        fill="none"
        stroke={TIER_COLOR[tier]}
        strokeWidth="4"
        strokeDasharray={len}
        strokeDashoffset={len * (1 - Math.min(100, risk) / 100)}
        style={{ transition: "stroke-dashoffset 900ms ease, stroke 600ms" }}
      />
      <text x="32" y="33" textAnchor="middle" className="font-mono" fontSize="14" fill="var(--color-bone)">
        {risk}
      </text>
    </svg>
  );
}

/** DOPPEL with its double: a faded, slightly drifted mirror image beneath. */
/** size: px, or any CSS length such as clamp(…) so the wordmark can scale with the viewport. */
export function Wordmark({ size = 28, mirror = true }: { size?: number | string; mirror?: boolean }) {
  return (
    <span className="relative inline-block font-display font-bold leading-none tracking-[0.18em] text-bone" style={{ fontSize: size }}>
      DOPPEL
      {mirror && <span
        aria-hidden
        className="pointer-events-none absolute left-0 top-[78%] block text-oxblood-hi/45 blur-[0.4px]"
        style={{
          transform: "scaleY(-1) translateX(0.05em)",
          maskImage: "linear-gradient(to top, black, transparent 70%)",
          WebkitMaskImage: "linear-gradient(to top, black, transparent 70%)",
        }}
      >
        DOPPEL
      </span>}
    </span>
  );
}
