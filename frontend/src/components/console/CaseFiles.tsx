import { AnimatePresence, motion } from "framer-motion";
import { Link } from "react-router-dom";
import { clockTime, type Alert } from "../../api";
import { SectionHead, TierBadge } from "../ui";

export function CaseFiles({ alerts }: { alerts: Alert[] }) {
  return (
    <section className="flex min-h-0 flex-col">
      <SectionHead kicker="the drawer" title="Case files" plain="Alerts, each with a Drift Receipt explaining why." />
      <ul className="scroll-quiet flex min-h-0 flex-col gap-4 overflow-y-auto px-1 pb-2">
        {alerts.length === 0 && (
          <li className="text-bone-dim italic">
            No case files open. One is filed the moment a subject’s risk reaches WATCH (30).
          </li>
        )}
        <AnimatePresence initial={false}>
          {alerts.map((a, i) => (
            <motion.li
              key={a.alert_id}
              layout="position"
              initial={{ opacity: 0, y: -20, rotate: -2 }}
              animate={{ opacity: a.status === "resolved" ? 0.6 : 1, y: 0, rotate: i % 2 ? 0.5 : -0.6 }}
              transition={{ duration: 0.8, ease: "easeOut" }}
            >
              <Link to={`/case/${a.alert_id}`} className="parchment block rounded-[2px] p-4 transition-transform duration-300 hover:-translate-y-0.5">
                <div className="flex items-center justify-between">
                  <span className="label !text-sepia/70">case file / {a.alert_id.slice(0, 6)}</span>
                  <span className="font-mono text-[12px] text-sepia/70">{clockTime(a.created_at)}</span>
                </div>
                <p className="mt-1 font-display text-[19px] leading-snug font-semibold">
                  {a.receipt?.headline_short || a.headline}
                </p>
                <div className="mt-3 flex items-center gap-3 border-t border-parch-edge/60 pt-2">
                  <span className="font-mono text-[22px] leading-none font-medium text-oxblood">{a.risk}</span>
                  <TierBadge tier={a.tier} />
                  <span className="ml-auto truncate font-mono text-[12px] text-sepia/70">{a.agent_id}</span>
                </div>
                {a.status === "resolved" && <span className="label mt-1 block !text-sepia/70">resolved · restored by a human</span>}
              </Link>
            </motion.li>
          ))}
        </AnimatePresence>
      </ul>
    </section>
  );
}
