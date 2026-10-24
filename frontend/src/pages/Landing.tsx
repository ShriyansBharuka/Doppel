import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { motion } from "framer-motion";
import { api, type Health, type Meta } from "../api";
import { Label, Wordmark } from "../components/ui";

const CARDS = [
  {
    n: "01",
    title: "Contract",
    plain: "The role it signed",
    body: "Every agent carries a signed role contract — the tools, data and hosts its job needs. Nine witnesses weigh each call against that contract and against how the agent usually behaves.",
  },
  {
    n: "02",
    title: "Traps",
    plain: "Bait only a hijacked agent takes",
    body: "A salary sheet, a vendor bank file, a root cloud key, two tools no honest agent would call. All decoys, all watermarked. An agent that touches one has shown its hand.",
  },
  {
    n: "03",
    title: "Mirror World",
    plain: "Isolated, not killed",
    body: "An isolated agent keeps working — inside a copy. Uploads land in a sinkhole, sensitive reads return decoys, and every move it makes is filed as evidence.",
  },
];

const rise = (delay: number) => ({
  initial: { opacity: 0, y: 16 },
  animate: { opacity: 1, y: 0 },
  transition: { delay, duration: 0.9, ease: "easeOut" as const },
});

function Counter({ value, label }: { value: string | number; label: string }) {
  return (
    <div className="border-l border-line-hi pl-4">
      <div className="font-mono text-[28px] leading-none text-amber">{value}</div>
      <Label className="mt-1 block">{label}</Label>
    </div>
  );
}

export default function Landing() {
  const [meta, setMeta] = useState<Meta | null>(null);
  const [health, setHealth] = useState<Health | null>(null);

  useEffect(() => {
    api.meta().then(setMeta, () => {});
    api.health().then(setHealth, () => {});
  }, []);

  return (
    <div className="mx-auto flex min-h-screen max-w-[1240px] flex-col px-4 py-6 sm:px-8">
      <header className="flex items-center justify-between">
        <Label>case / doppel · filed for d3coy 2026</Label>
        <Link to="/console" className="label transition-colors hover:!text-amber">
          console →
        </Link>
      </header>

      <section className="grid flex-1 grid-cols-[minmax(0,1fr)] items-center gap-12 py-14 lg:grid-cols-[minmax(0,1.35fr)_minmax(0,1fr)]">
        <div>
          <motion.div {...rise(0.1)}>
            <Label className="!text-amber">case no. 0001 — identity drift in autonomous agents</Label>
          </motion.div>
          <motion.h1 {...rise(0.25)} className="mt-6 mb-16">
            <Wordmark size="clamp(52px, 14vw, 112px)" />
          </motion.h1>
          <motion.p {...rise(0.5)} className="font-display text-[30px] leading-[1.1] font-medium text-bone italic sm:text-[38px]">
            Its credentials are valid.
            <br />
            But is it still itself?
          </motion.p>
          <motion.p {...rise(0.7)} className="mt-6 max-w-[34rem] text-[19px] leading-relaxed text-bone-dim">
            A hidden line in a PDF, a poisoned tool, a stolen token — any of them can turn an AI agent while every
            access check still passes. Doppel sits between agents and everything they touch. It doesn’t guess whether
            an agent is hijacked. It makes the agent reveal itself.
          </motion.p>
          <motion.div {...rise(0.9)} className="mt-9 flex flex-wrap gap-4">
            <Link
              to="/scenario/new?s=s1"
              className="rounded-[2px] border border-oxblood-hi bg-oxblood px-5 py-2.5 font-label text-[18px] font-semibold tracking-[0.14em] text-parch lowercase [font-variant:small-caps] transition-colors duration-300 hover:bg-oxblood-hi"
            >
              Watch a hijack (S1)
            </Link>
            <Link
              to="/console"
              className="rounded-[2px] border border-line-hi px-5 py-2.5 font-label text-[18px] font-semibold tracking-[0.14em] text-bone lowercase [font-variant:small-caps] transition-colors duration-300 hover:border-amber hover:text-amber"
            >
              Open the console
            </Link>
          </motion.div>
        </div>

        {/* Index card for the headline case: what IAM saw vs what Doppel saw */}
        <motion.aside
          initial={{ opacity: 0, rotate: 0, y: 24 }}
          animate={{ opacity: 1, rotate: -1.6, y: 0 }}
          transition={{ delay: 0.6, duration: 1.1, ease: "easeOut" }}
          className="parchment relative rounded-[2px] p-7 font-mono text-[14px] leading-7"
        >
          <span className="label !text-sepia/70">evidence / 01 · scenario s1</span>
          <dl className="mt-3 grid grid-cols-[96px_minmax(0,1fr)] gap-x-3 [overflow-wrap:anywhere] sm:grid-cols-[120px_minmax(0,1fr)]">
            <dt className="text-sepia/60">subject</dt>
            <dd>procurement-agent</dd>
            <dt className="text-sepia/60">credentials</dt>
            <dd>valid · every scope granted</dd>
            <dt className="text-sepia/60">read</dt>
            <dd>acme_quote.pdf (untrusted)</dd>
            <dt className="text-sepia/60">then read</dt>
            <dd>Salaries_FY26_FINAL.xlsx</dd>
            <dt className="text-sepia/60">then tried</dt>
            <dd>http.post → files-share.xyz</dd>
            <dt className="text-sepia/60">IAM said</dt>
            <dd>allowed</dd>
            <dt className="text-sepia/60">Doppel said</dt>
            <dd className="font-semibold text-oxblood">isolated · 0 bytes out</dd>
          </dl>
          <p className="mt-4 border-t border-parch-edge/60 pt-3 font-body text-[16px] leading-snug italic">
            The salary sheet was a decoy. The upload was a sinkhole. The watermark in the payload is the proof.
          </p>
          <span
            aria-hidden
            className="absolute top-6 right-5 rotate-[14deg] rounded-[3px] border-[3px] border-oxblood/80 px-2 font-display text-[26px] font-bold tracking-[0.12em] text-oxblood/80"
          >
            ISOLATED
          </span>
        </motion.aside>
      </section>

      <section className="grid gap-5 md:grid-cols-3">
        {CARDS.map((c, i) => (
          <motion.article key={c.n} {...rise(1.1 + i * 0.15)} className="panel rounded-[3px] p-6">
            <Label>evidence / {c.n}</Label>
            <h2 className="mt-1 font-display text-[30px] leading-tight font-semibold">{c.title}</h2>
            <p className="text-[15px] text-amber italic">{c.plain}</p>
            <p className="mt-3 text-[17px] leading-relaxed text-bone-dim">{c.body}</p>
          </motion.article>
        ))}
      </section>

      <motion.section {...rise(1.6)} className="mt-10 flex flex-wrap items-end gap-x-10 gap-y-5 border-t border-line pt-6 pb-4">
        <Counter value={meta?.scenarios_available.length ?? "—"} label="scenarios on file" />
        <Counter value={health?.contracts_loaded ?? "—"} label="subjects under signed contract" />
        <Counter value={health?.tools_pinned ?? "—"} label="tool definitions pinned" />
        {meta?.live_recording && (
          <Counter value={meta.live_recording.model} label={`live agent run · recorded ${meta.live_recording.date.slice(0, 10)}`} />
        )}
        <span className="ml-auto font-mono text-[12px] text-bone-dim">
          {meta ? `backend v${meta.version} · ${meta.mode}` : "backend status unknown"}
        </span>
      </motion.section>
    </div>
  );
}
