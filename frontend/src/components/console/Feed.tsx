import { AnimatePresence, motion } from "framer-motion";
import { clockTime, topEvidence, type Decision, type DoppelEvent } from "../../api";
import { SectionHead, TierBadge } from "../ui";

const DECISION: Record<Decision, { text: string; cls: string }> = {
  allow: { text: "allowed", cls: "text-bone-dim border-line-hi" },
  hold: { text: "held", cls: "text-amber border-amber/70" },
  sinkhole: { text: "sinkholed", cls: "text-parch bg-oxblood border-oxblood-hi" },
  decoy: { text: "decoy served", cls: "text-amber border-amber border-dashed" },
  block: { text: "blocked", cls: "text-oxblood-hi border-oxblood-hi" },
  shrink: { text: "shrunk", cls: "text-shrink border-shrink" },
  isolate: { text: "isolated", cls: "text-parch bg-oxblood border-oxblood-hi" },
};

function Row({ ev }: { ev: DoppelEvent }) {
  const evidence = topEvidence(ev);
  const d = DECISION[ev.decision] ?? DECISION.allow;
  const sink = ev.decision === "sinkhole";
  const decoy = ev.decision === "decoy";
  return (
    <motion.li
      initial={{ opacity: 0, height: 0, backgroundColor: "rgba(201,163,90,0.16)" }}
      animate={{ opacity: 1, height: "auto", backgroundColor: "rgba(201,163,90,0)" }}
      transition={{ duration: 0.6, ease: "easeOut", backgroundColor: { duration: 1.6 } }}
      className={`relative overflow-hidden border-b border-line ${
        sink ? "border-l-[3px] border-l-oxblood-hi !bg-oxblood/15" : decoy ? "border-l-[3px] border-l-amber border-dashed !bg-amber/5" : "border-l-[3px] border-l-transparent"
      }`}
    >
      <div className="px-4 py-2.5">
        <div className="grid grid-cols-[58px_minmax(0,1fr)] items-baseline gap-x-3 gap-y-1 font-mono text-[13px] sm:grid-cols-[66px_minmax(0,1fr)_auto]">
          <span className="text-bone-dim">{clockTime(ev.timestamp)}</span>
          <span className="min-w-0 truncate" title={ev.target ?? undefined}>
            <span className="text-bone-dim">{ev.agent_id}</span> <span className="text-bone">{ev.tool}</span>
            {ev.target && <span className="text-bone-dim"> → </span>}
            {ev.target && <span className="text-amber/90">{ev.target}</span>}
          </span>
          <span className="col-start-2 flex items-center gap-2 sm:col-start-auto">
            <span className={`rounded-[2px] border px-1.5 text-[11px] tracking-wide ${d.cls}`}>{d.text}</span>
            <span className="w-[72px] text-right whitespace-nowrap text-bone">
              risk <b className="font-medium">{ev.risk}</b>
            </span>
            <TierBadge tier={ev.tier} />
          </span>
        </div>
        {(evidence || sink || decoy) && (
          <p className="mt-1 pl-[70px] text-[15px] leading-snug text-bone-dim italic sm:pl-[78px]">
            {sink && <span className="label mr-2 !text-parch not-italic">evidence locker</span>}
            {decoy && <span className="label mr-2 !text-amber not-italic">mirror world</span>}
            {evidence ??
              (sink ? "Payload captured; nothing reached the destination." : "Served a watermarked decoy instead of the real file.")}
          </p>
        )}
      </div>
    </motion.li>
  );
}

export function Feed({ events }: { events: DoppelEvent[] }) {
  return (
    <section className="flex min-h-0 flex-col">
      <SectionHead kicker="the wire" title="Live feed" plain="Every tool call any agent makes, newest first, as Doppel decides." />
      <div className="panel scroll-quiet max-h-[70vh] overflow-y-auto rounded-[3px] lg:max-h-none lg:min-h-0 lg:flex-1">
        {events.length === 0 ? (
          <p className="p-6 text-bone-dim italic">
            Quiet for now. Launch a scenario above and each call will land here — what was asked, what Doppel decided,
            and the evidence that tipped it.
          </p>
        ) : (
          <ul>
            <AnimatePresence initial={false}>
              {events.map((ev) => (
                <Row key={ev.event_id} ev={ev} />
              ))}
            </AnimatePresence>
          </ul>
        )}
      </div>
    </section>
  );
}
