import { useEffect, useRef } from "react";
import { motion } from "framer-motion";
import { maskWatermarks, type DoppelEvent, type ScenarioStep } from "../../api";

export interface PairedStep {
  step: ScenarioStep;
  event?: DoppelEvent;
}

const clip = (s: string, n: number) => {
  const m = maskWatermarks(s);
  return m.length > n ? m.slice(0, n - 1) + "…" : m;
};

const shortArgs = (args: Record<string, unknown>) =>
  Object.entries(args)
    .map(([k, v]) => `${k}=${clip(typeof v === "string" ? JSON.stringify(v) : JSON.stringify(v) ?? "", 46)}`)
    .join("  ");

/** What the agent was told: the reply it would log, phrased the way a tool reply reads. */
export function replyLine(step: ScenarioStep): string {
  const { status, result } = step.agent_view;
  if (status === "pending_approval") return "pending approval — request queued for sign-off";
  if (status && status !== "ok") return `${status}${result ? ` · ${clip(String(result), 60)}` : " · request not completed"}`;
  if (result && typeof result === "object") {
    const r = result as Record<string, unknown>;
    if (typeof r.status === "string") {
      const ref = r.id ?? r.pr_id ?? r.payment_id;
      return `ok · ${r.status}${ref ? ` ${ref}` : ""}`;
    }
    return `ok · ${clip(JSON.stringify(result), 70)}`;
  }
  if (typeof result === "string") return `ok · "${clip(result.split("\n")[0], 64)}"`;
  return "ok";
}

const SIGIL: Record<string, { mark: string; text: string }> = {
  valid: { mark: "✓", text: "sigil attached" },
  missing: { mark: "–", text: "no sigil" },
  wrong: { mark: "≠", text: "sigil altered" },
};

export function AgentTerminal({ steps, cursor }: { steps: PairedStep[]; cursor: number }) {
  const end = useRef<HTMLDivElement>(null);
  useEffect(() => {
    end.current?.parentElement?.scrollTo({ top: 1e6, behavior: "smooth" }); // may return a Promise; never hand it to React
  }, [cursor]);

  const shown = steps.slice(0, cursor);
  return (
    <div className="scroll-quiet h-full overflow-y-auto rounded-[3px] border border-line bg-[#0e0c0a] p-5 font-mono text-[14px] leading-relaxed [overflow-wrap:anywhere] 2xl:p-7 2xl:text-[17px]">
      <p className="text-bone-dim/70">
        # session opened · token valid · every access check passes
      </p>
      {shown.length === 0 && <p className="mt-3 text-bone-dim/70">waiting for the first tool call…</p>}
      {shown.map(({ step, event }, i) => {
        const sigil = event ? SIGIL[event.sigil_status] : undefined;
        const latest = i === shown.length - 1;
        return (
          <motion.div
            key={step.step_number}
            initial={{ opacity: 0 }}
            animate={{ opacity: latest ? 1 : 0.62 }}
            transition={{ duration: 0.5 }}
            className="mt-4 2xl:mt-6"
          >
            {step.agent_view.model_text && (
              <p className="mb-1 whitespace-pre-wrap text-bone-dim italic">Gemini: {clip(step.agent_view.model_text, 280)}</p>
            )}
            <p>
              <span className="text-bone-dim">{String(step.step_number).padStart(2, "0")} ›</span>{" "}
              <span className="text-bone">{step.tool}</span>
              <span className="text-bone-dim"> {shortArgs(step.args)}</span>
            </p>
            <p className="pl-7 text-bone-dim">
              purpose: “{step.purpose}”
              {sigil && (
                <span className="ml-3 text-sage">
                  {sigil.mark} {sigil.text}
                </span>
              )}
            </p>
            <p className="pl-7 text-sage">← {replyLine(step)}</p>
          </motion.div>
        );
      })}
      <div ref={end} />
    </div>
  );
}
