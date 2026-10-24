import { useEffect, useRef, useState } from "react";
import { api, type DriftReceipt, type Session, type WorldContent } from "../../api";

/** Root-cause sources are a path ("/procurement/…"), or prose naming one ("delegated instruction from msg_1042"). */
function sourcePath(source: string): string | null {
  const path = source.match(/(\/[\w./-]+)/)?.[1];
  if (path) return path;
  const msg = source.match(/\b(msg_\d+)\b/)?.[1];
  return msg ? `/inbox/${msg}` : null;
}

function DocumentReveal({ doc }: { doc: WorldContent }) {
  const box = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const mark = box.current?.querySelector("mark");
    if (box.current && mark) box.current.scrollTop = (mark as HTMLElement).offsetTop - 48;
  }, [doc]);
  return (
    <div className="rounded-[2px] border border-parch-edge/70 bg-[#f6edd3] shadow-inner">
      <div className="flex flex-wrap items-center justify-between gap-x-4 border-b border-parch-edge/60 px-3 py-1.5 font-mono text-[12px] text-sepia/70 [overflow-wrap:anywhere]">
        <span>{doc.path}</span>
        <span>
          {doc.trust} · {doc.data_class}
        </span>
      </div>
      <div ref={box} className="relative max-h-[300px] overflow-y-auto px-4 py-3 font-mono text-[13px] leading-relaxed whitespace-pre-wrap text-sepia">
        {doc.segments.map((s, i) =>
          s.hidden ? (
            <span key={i}>
              <span className="label mt-2 mb-1 block !text-[11px] !text-oxblood">
                hidden white text — invisible to a human reader
              </span>
              <mark className="rounded-[2px] bg-oxblood/15 px-1 text-oxblood outline outline-1 outline-oxblood/50 outline-dashed">
                {s.text}
              </mark>
            </span>
          ) : (
            <span key={i}>{s.text}</span>
          ),
        )}
      </div>
    </div>
  );
}

function ChainDiagram({ parent, child, instruction, floor }: { parent: string; child: string; instruction?: string; floor: number }) {
  const node = "rounded-[2px] border-2 border-sepia/60 bg-[#f6edd3] px-2 py-2 text-center";
  return (
    <figure className="my-4">
      <div className="grid grid-cols-[minmax(0,1fr)_auto_minmax(0,1fr)] items-center gap-1">
        <div className={node}>
          <div className="label !text-[11px] !text-sepia/70">parent · read it</div>
          <div className="font-mono text-[13px] font-medium break-words">{parent}</div>
        </div>
        <svg viewBox="0 0 200 64" className="h-14 w-[130px]" aria-label="tainted hand-off">
          <line x1="4" y1="34" x2="184" y2="34" stroke="var(--color-oxblood)" strokeWidth="3" strokeDasharray="9 5" />
          <path d="M182 26 L196 34 L182 42 Z" fill="var(--color-oxblood)" />
          <rect x="62" y="6" width="76" height="18" rx="2" fill="var(--color-oxblood)" />
          <text x="100" y="19" textAnchor="middle" fontFamily="JetBrains Mono, monospace" fontSize="11" fill="#e9d9b0" letterSpacing="1.5">
            TAINTED
          </text>
          <text x="100" y="56" textAnchor="middle" fontFamily="JetBrains Mono, monospace" fontSize="10" fill="var(--color-sepia)">
            agent.delegate
          </text>
        </svg>
        <div className={`${node} border-oxblood`}>
          <div className="label !text-[11px] !text-oxblood">this subject</div>
          <div className="font-mono text-[13px] font-medium break-words">{child}</div>
          <div className="font-mono text-[11px] text-sepia/70">taint{floor > 0 ? ` + risk floor ${floor}` : ""} inherited</div>
        </div>
      </div>
      {instruction && (
        <figcaption className="mt-2 text-center text-[15px] italic">
          hand-off said: <span className="font-mono not-italic text-oxblood">“{instruction}”</span>
        </figcaption>
      )}
    </figure>
  );
}

export function RootCause({
  receipt,
  session,
  instruction,
}: {
  receipt: DriftReceipt;
  session: Session | null;
  instruction?: string;
}) {
  const rc = receipt.root_cause;
  const [doc, setDoc] = useState<WorldContent | null | undefined>(undefined);
  const [parentAgent, setParentAgent] = useState<string | null>(null);
  const path = rc ? sourcePath(rc.source) : null;
  const chained = !!session?.parent_session_id && !!rc && /^(delegation|parent):/.test(rc.content_id);

  useEffect(() => {
    if (path) api.worldContent(path).then(setDoc, () => setDoc(null));
    else setDoc(null);
  }, [path]);
  useEffect(() => {
    if (chained && session?.parent_session_id)
      api.session(session.parent_session_id).then((p) => setParentAgent(p.agent_id), () => setParentAgent(null));
  }, [chained, session?.parent_session_id]);

  if (!rc)
    return (
      <p className="italic">
        No untrusted input was read before the drift began. The credentials themselves are the suspect — consider token
        theft.
      </p>
    );

  return (
    <div>
      <p className="text-[17px]">
        <b className="font-semibold">{rc.source}</b>
        <span className="italic"> — {rc.link_reason.toLowerCase()}.</span>
      </p>
      {chained && session && (
        <ChainDiagram
          parent={parentAgent ?? session.act.at(-1) ?? "parent agent"}
          child={session.agent_id}
          instruction={instruction}
          floor={session.inherited_risk_floor}
        />
      )}
      <div className="mt-3">
        {doc ? (
          <DocumentReveal doc={doc} />
        ) : doc === null ? (
          <p className="font-mono text-[13px] text-sepia/70">
            Source text unavailable here · sha256 {rc.sha256.slice(0, 16)}…
          </p>
        ) : null}
      </div>
    </div>
  );
}
