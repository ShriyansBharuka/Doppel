import type { ScenarioMeta } from "../../api";
import { Button, Label } from "../ui";

/** "PDF Hijack (Indirect Prompt Injection)" → ["PDF Hijack", "Indirect Prompt Injection"] */
const splitName = (n: string) => {
  const m = n.match(/^(.*?)\s*\((.*)\)$/);
  return m ? [m[1], m[2]] : [n, ""];
};

export function Launcher({ scenarios, onRun }: { scenarios: ScenarioMeta[]; onRun: (id: string) => void }) {
  return (
    <section className="border-b border-line px-4 py-3 lg:px-6">
      <div className="mb-2 flex items-baseline gap-x-4">
        <Label>scenario launcher</Label>
        <span className="text-[15px] text-bone-dim italic">
          Stage an attack against the simulated company. Each run resets the world and opens the two views.
        </span>
      </div>
      <ul className="scroll-quiet grid auto-cols-[minmax(176px,1fr)] grid-flow-col gap-2 overflow-x-auto pb-1">
        {scenarios.map((s) => {
          const [name, sub] = splitName(s.name);
          return (
            <li key={s.id} className="panel flex flex-col rounded-[3px] p-3">
              <div className="flex items-baseline justify-between gap-2">
                <span className="font-mono text-[12px] text-amber">{s.id.toUpperCase()}</span>
                <Button
                  variant={s.id === "s1" ? "blood" : "ghost"}
                  className="!px-2 !py-0.5 !text-[14px]"
                  disabled={s.expected_outcome === "Unavailable"}
                  onClick={() => onRun(s.id)}
                >
                  run
                </Button>
              </div>
              <p className="mt-1 font-display text-[18px] leading-tight font-semibold">{name}</p>
              {sub && <p className="text-[13px] leading-tight text-bone-dim">{sub}</p>}
              <p className="mt-1 line-clamp-2 text-[13px] leading-snug text-bone-dim/80 italic" title={s.description}>
                {s.description}
              </p>
            </li>
          );
        })}
      </ul>
    </section>
  );
}
