import { motion } from "framer-motion";
import { tierOf, type AgentDetail } from "../../api";
import { Label, RiskGauge, SectionHead, TierBadge } from "../ui";

export function Subjects({ agents, liveRisk }: { agents: AgentDetail[]; liveRisk: Record<string, number> }) {
  return (
    <section className="flex min-h-0 flex-col">
      <SectionHead kicker="witness list" title="Subjects" plain="The agents under watch, and the worst risk each has reached." />
      <ul className="scroll-quiet flex min-h-0 flex-col gap-3 overflow-y-auto pr-1">
        {agents.map((a, i) => {
          const risk = Math.max(a.max_risk, liveRisk[a.agent_id] ?? 0);
          const tier = tierOf(risk);
          return (
            <motion.li
              key={a.agent_id}
              initial={{ opacity: 0, x: -10 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: i * 0.12, duration: 0.6 }}
              className={`panel rounded-[3px] px-4 py-3 transition-colors duration-700 ${
                tier === "ISOLATE" ? "border-oxblood-hi pulse-isolate" : tier === "SHRINK" ? "border-shrink/60" : ""
              }`}
            >
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <Label>subject / {String(i + 1).padStart(2, "0")}</Label>
                  <h3 className="font-display text-[21px] leading-tight font-semibold">{a.role}</h3>
                  <p className="truncate font-mono text-[12px] text-bone-dim">{a.agent_id}</p>
                </div>
                <RiskGauge risk={risk} tier={tier} />
              </div>
              <p className="truncate text-[15px] text-bone-dim italic" title={a.purpose}>
                {a.purpose}
              </p>
              <div className="mt-1.5 flex items-center justify-between">
                <span className="font-mono text-[12px] text-bone-dim">contract v{a.contract_version} · signed</span>
                <TierBadge tier={tier} />
              </div>
            </motion.li>
          );
        })}
      </ul>
    </section>
  );
}
