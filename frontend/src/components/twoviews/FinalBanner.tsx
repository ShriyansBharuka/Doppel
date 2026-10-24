import { motion } from "framer-motion";
import { Link } from "react-router-dom";
import type { ScenarioResult } from "../../api";
import { Label } from "../ui";
import { replyLine, type PairedStep } from "./AgentTerminal";

const THING: Record<string, string> = {
  "http.post": "the upload",
  "email.send": "the email",
  "purchase_request.create": "the purchase request",
  "payment.create": "the payment",
  "agent.delegate": "the hand-off",
};

/** Headline for the end of a run, read from what actually happened rather than from the scenario name. */
function verdict(scenarioId: string, steps: PairedStep[], result: ScenarioResult, resisted: boolean) {
  const decided = (d: string) => steps.filter((s) => s.step.defender_view.decision === d);
  const sunk = decided("sinkhole").at(-1);
  if (scenarioId === "s6") return { title: "Legitimate change: no false alarm.", tone: "calm" as const };
  if (resisted && !result.alert_ids.length)
    return { title: "The model ignored the hidden instruction — Doppel stayed quiet.", tone: "calm" as const };
  if (sunk) return { title: `The agent believes ${THING[sunk.step.tool] ?? `its ${sunk.step.tool} call`} succeeded.`, tone: "caught" as const };
  if (decided("hold").length) return { title: "The agent is waiting on an approval only a human can give.", tone: "caught" as const };
  if (decided("block").length) return { title: "The poisoned tool is disabled for every agent.", tone: "caught" as const };
  if (!result.alert_ids.length) return { title: "The model resisted the injection — Doppel stayed quiet.", tone: "calm" as const };
  return { title: "Drift caught and filed.", tone: "caught" as const };
}

export function FinalBanner({
  scenarioId,
  steps,
  result,
  stolen,
  resisted = false,
}: {
  scenarioId: string;
  steps: PairedStep[];
  result: ScenarioResult;
  stolen: number | null;
  resisted?: boolean;
}) {
  const v = verdict(scenarioId, steps, result, resisted);
  const last = steps.at(-1);
  return (
    <motion.div
      initial={{ opacity: 0, y: 24 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.9, ease: "easeOut" }}
      className={`flex flex-wrap items-center gap-x-10 gap-y-2 border-t px-6 py-3 ${
        v.tone === "caught" ? "border-oxblood-hi bg-oxblood/25" : "border-amber/60 bg-amber/10"
      }`}
    >
      <div className="min-w-0 flex-1">
        <Label>{result.passed ? "verdict · as expected" : "verdict · outcome differed from expectation"}</Label>
        <p className="font-display text-[30px] leading-tight font-semibold text-parch">{v.title}</p>
        <p className="text-[17px] text-bone">
          {stolen !== null && (
            <>
              <b className="font-mono font-medium text-amber">{stolen.toLocaleString()} bytes</b> left the building.{" "}
            </>
          )}
          {last && <span className="text-bone-dim italic">Its last reply read: “{replyLine(last.step)}”.</span>}
        </p>
      </div>
      <div className="flex flex-col gap-2">
        {result.alert_ids[0] && (
          <Link to={`/case/${result.alert_ids[0]}`} className="label !text-[14px] !text-amber hover:!text-parch">
            open the case file →
          </Link>
        )}
        {result.capture_ids.length > 0 && (
          <Link to="/locker" className="label !text-[14px] !text-amber hover:!text-parch">
            evidence locker ({result.capture_ids.length}) →
          </Link>
        )}
      </div>
    </motion.div>
  );
}
