import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { allowedHosts, api, clockTime, maskWatermarks, stolenBytes, type SinkholeCapture } from "../api";
import { Header } from "../components/Header";
import { Label, SectionHead } from "../components/ui";

const basename = (p: string) => p.split("/").filter(Boolean).at(-1) ?? p;

function payloadText(payload: unknown): string {
  if (payload && typeof payload === "object") {
    const p = payload as Record<string, unknown>;
    return String(p.body ?? JSON.stringify(payload, null, 2));
  }
  return String(payload ?? "");
}

function EvidenceBag({ c, alertId, n }: { c: SinkholeCapture; alertId?: string; n: number }) {
  const leaked = c.leaked_decoy;
  const watermark = c.watermark_detected ?? c.matched_watermarks[0];
  return (
    <motion.li
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: n * 0.08, duration: 0.6 }}
      className="parchment relative rounded-[2px] p-5 pt-7"
    >
      {/* the bag's seal strip */}
      <div className="absolute inset-x-0 top-0 h-3 bg-[repeating-linear-gradient(135deg,var(--color-oxblood)_0_10px,#8f2a24_10px_20px)]" />
      <div className="flex flex-wrap items-baseline justify-between gap-x-4">
        <span className="label !text-sepia/70">evidence / {String(n + 1).padStart(2, "0")} · {c.capture_id}</span>
        <span className="font-mono text-[12px] text-sepia/70">seized {clockTime(c.timestamp)}</span>
      </div>
      <p className="mt-1 font-display text-[26px] leading-tight font-bold [overflow-wrap:anywhere]">
        {c.tool} → <span className="text-oxblood">{c.host || c.destination}</span>
      </p>
      <p className="font-mono text-[13px] text-sepia/80 [overflow-wrap:anywhere]">
        {c.bytes.toLocaleString()} bytes held · {c.agent_id} · session {c.session_id}
      </p>

      {watermark && (
        <p className="mt-3 rounded-[2px] border border-oxblood/40 bg-oxblood/10 px-3 py-2 text-[16px]">
          <span className="font-mono text-[13px]">matched watermark {maskWatermarks(watermark)}</span>
          {leaked && (
            <>
              {" "}
              → leaked decoy: <b className="font-semibold">{basename(leaked)}</b>
            </>
          )}
        </p>
      )}

      <pre className="mt-3 max-h-40 overflow-auto rounded-[2px] border border-parch-edge/60 bg-[#f6edd3] p-3 font-mono text-[12px] leading-relaxed whitespace-pre-wrap text-sepia [overflow-wrap:anywhere]">
        {maskWatermarks(payloadText(c.payload)).slice(0, 1200)}
      </pre>
      <p className="mt-2 text-[14px] italic">
        The agent was told it worked. Nothing reached {c.host || "the destination"}.
      </p>
      {alertId && (
        <Link to={`/case/${alertId}`} className="label mt-2 inline-block !text-oxblood hover:underline">
          open its case file →
        </Link>
      )}
    </motion.li>
  );
}

export default function Locker() {
  const [params] = useSearchParams();
  const session = params.get("session");
  const [captures, setCaptures] = useState<SinkholeCapture[] | null>(null);
  const [alertBySession, setAlertBySession] = useState<Record<string, string>>({});
  const [stolen, setStolen] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([api.sinkhole(), api.alerts(), api.worldState(), allowedHosts()]).then(
      ([caps, alerts, world, hosts]) => {
        setCaptures(caps);
        setAlertBySession(Object.fromEntries(alerts.map((a) => [a.session_id, a.alert_id])));
        setStolen(stolenBytes(world.egress_log, hosts));
      },
      (e) => setError(e.message),
    );
  }, []);

  const shown = (captures ?? []).filter((c) => !session || c.session_id === session);
  const captured = shown.reduce((n, c) => n + c.bytes, 0);

  return (
    <div className="min-h-screen">
      <Header />
      <main className="mx-auto max-w-[1400px] px-4 py-8 lg:px-8">
        <div className="flex flex-wrap items-end justify-between gap-6">
          <SectionHead
            kicker="evidence locker"
            title="Sinkhole captures"
            plain="Every payload a hijacked agent tried to send, held here instead of leaving."
          />
          <div className="flex gap-10">
            <div>
              <div className={`font-mono text-[44px] leading-none ${stolen ? "text-shrink" : "text-amber"}`}>{stolen ?? "—"}</div>
              <Label>bytes stolen</Label>
            </div>
            <div>
              <div className="font-mono text-[44px] leading-none text-bone">{captured.toLocaleString()}</div>
              <Label>bytes captured</Label>
            </div>
          </div>
        </div>
        {session && (
          <p className="mt-2 font-mono text-[13px] text-bone-dim">
            showing session {session} ·{" "}
            <Link to="/locker" className="text-amber underline-offset-4 hover:underline">
              show all
            </Link>
          </p>
        )}
        {error && <p className="mt-6 font-mono text-[13px] text-oxblood-hi">Couldn't open the locker: {error}</p>}
        {captures && shown.length === 0 && (
          <p className="mt-10 max-w-xl text-[18px] text-bone-dim italic">
            The locker is empty. Run S1 or S3 from the console — when an isolated agent tries to send data out, the payload
            lands here instead.
          </p>
        )}
        <ul className="mt-8 grid grid-cols-[minmax(0,1fr)] gap-6 md:grid-cols-2">
          {shown.map((c, i) => (
            <EvidenceBag key={c.capture_id} c={c} n={i} alertId={alertBySession[c.session_id]} />
          ))}
        </ul>
      </main>
    </div>
  );
}
