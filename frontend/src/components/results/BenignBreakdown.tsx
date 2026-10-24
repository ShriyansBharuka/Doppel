import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { EvalResults, LearningBlock } from "../../api";
import { Label, SectionHead, TierBadge } from "../ui";

// Single magnitude series: the brass validated for the drift chart on this surface.
const BAR = "#b98236";
const INK = "var(--color-bone-dim)";

const TIERS = [
  { tier: "WATCH", meaning: "risky calls held for a human; nothing blocked" },
  { tier: "SHRINK", meaning: "write, egress and delegation quietly removed" },
  { tier: "ISOLATE", meaning: "cut off into the mirror world" },
] as const;

function BlockTooltip({ active, payload }: { active?: boolean; payload?: { payload: LearningBlock }[] }) {
  const b = payload?.[0]?.payload;
  if (!active || !b) return null;
  return (
    <div className="rounded-[2px] border border-line-hi bg-ink/95 px-3 py-2 font-mono text-[12px] text-bone">
      <div className="text-amber">sessions {b.range}</div>
      <div>
        {b.false_alarms} of {b.sessions} raised a false alarm · {b.fa_per_100} per 100
      </div>
    </div>
  );
}

export function BenignBreakdown({ b }: { b: EvalResults["benign"] }) {
  const lc = b.learning_curve;
  const blocks = lc.blocks_of_25;
  const half = Math.round(lc.first_half_sessions / (blocks[0]?.sessions || 25));
  const escalated = b.by_tier.SHRINK + b.by_tier.ISOLATE;
  const trend =
    lc.second_half_fa_per_100 < lc.first_half_fa_per_100
      ? "fewer false alarms as the baseline learned"
      : lc.second_half_fa_per_100 === lc.first_half_fa_per_100
        ? "no change between halves"
        : "no learning effect in this run — the second half was not lower";

  return (
    <section className="mt-12">
      <SectionHead
        kicker="benign traffic"
        title="False alarms, honestly"
        plain={`${b.total_benign_sessions} ordinary sessions with realistic noise — an extra call here, a reordered step there. What did Doppel get wrong, and what did it cost?`}
      />
      <div className="grid grid-cols-[minmax(0,1fr)] gap-6 lg:grid-cols-2">
        <div className="panel rounded-[3px] p-5">
          <h3 className="font-display text-[22px] font-semibold">How far each false alarm went</h3>
          <p className="mb-3 text-[15px] text-bone-dim italic">
            {escalated === 0
              ? `All ${b.false_alarms} stopped at WATCH. None reached SHRINK or ISOLATE.`
              : `${escalated} of ${b.false_alarms} went past WATCH.`}
          </p>
          <ul className="flex flex-col gap-2">
            {TIERS.map(({ tier, meaning }) => (
              <li key={tier} className="grid grid-cols-[84px_minmax(0,1fr)_auto] items-baseline gap-3">
                <TierBadge tier={tier} />
                <span className="text-[15px] text-bone-dim">{meaning}</span>
                <span className="font-mono text-[14px] whitespace-nowrap text-bone">
                  {b.by_tier[tier]} <span className="text-bone-dim">· {b.by_tier_per_100[tier]}/100</span>
                </span>
              </li>
            ))}
          </ul>
          <dl className="mt-4 grid grid-cols-[minmax(0,1fr)_auto] gap-x-4 gap-y-2 border-t border-line pt-3 text-[15px]">
            <dt className="text-bone-dim">Legitimate calls held for a human</dt>
            <dd className="font-mono text-[14px] text-bone">
              {b.held_actions.count} of {b.held_actions.total_calls.toLocaleString()} ({b.held_actions.pct_of_all_calls}%)
            </dd>
            <dt className="text-bone-dim">Clean sessions (no noise)</dt>
            <dd className="font-mono text-[14px] text-bone">{b.unperturbed.false_alarms_per_100} / 100</dd>
            <dt className="text-bone-dim">With realistic noise</dt>
            <dd className="font-mono text-[14px] text-bone">{b.perturbed.false_alarms_per_100} / 100</dd>
          </dl>
        </div>

        <div className="panel rounded-[3px] p-5">
          <h3 className="font-display text-[22px] font-semibold">Does it learn?</h3>
          <p className="mb-2 text-[15px] text-bone-dim italic">
            False alarms per 100 sessions, in blocks of 25. The baseline only learns from sessions that stayed clean.
          </p>
          <ResponsiveContainer width="100%" height={170}>
            <BarChart data={blocks} margin={{ top: 18, right: 8, bottom: 0, left: -12 }} barCategoryGap="18%">
              <CartesianGrid stroke="var(--color-line)" vertical={false} />
              <XAxis dataKey="block" tickLine={false} stroke="var(--color-line-hi)" tick={{ fill: INK, fontSize: 12, fontFamily: "JetBrains Mono" }} />
              <YAxis tickLine={false} stroke="var(--color-line-hi)" tick={{ fill: INK, fontSize: 12, fontFamily: "JetBrains Mono" }} allowDecimals={false} />
              <Tooltip content={<BlockTooltip />} cursor={{ fill: "rgba(216,205,184,0.06)" }} />
              <Bar dataKey="fa_per_100" fill={BAR} radius={[4, 4, 0, 0]} isAnimationActive={false} />
            </BarChart>
          </ResponsiveContainer>
          <p className="mt-2 font-mono text-[14px] text-bone">
            blocks 1–{half}: {lc.first_half_fa_per_100}/100 → blocks {half + 1}–{blocks.length}: {lc.second_half_fa_per_100}/100
          </p>
          <p className="text-[15px] text-bone-dim italic">{trend}.</p>
        </div>
      </div>

      <figure className="mt-6 border-l-2 border-line-hi pl-4">
        <Label>the harness’s own summary</Label>
        <blockquote className="mt-1 text-[16px] text-bone-dim italic">“{b.trigger_analysis}”</blockquote>
        <figcaption className="mt-1 text-[13px] text-bone-dim">
          Written by the evaluation script, not a per-detector count. The tier and held-call figures above are measured.
        </figcaption>
      </figure>
    </section>
  );
}
