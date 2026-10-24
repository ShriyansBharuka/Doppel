import { useRef, useState } from "react";
import { Link } from "react-router-dom";
import { api, type Alert, type Approval, type Session } from "../../api";
import { Button, Label, TierBadge } from "../ui";

const argLine = (args: Record<string, unknown>) =>
  Object.entries(args)
    .map(([k, v]) => `${k}: ${typeof v === "string" ? v : JSON.stringify(v)}`)
    .join(" · ");

export function HumanControls({
  alert,
  session,
  approvals,
  captures,
  rootSource,
  onChange,
}: {
  alert: Alert;
  session: Session | null;
  approvals: Approval[];
  captures: number;
  rootSource: string | null;
  onChange: () => void;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<string | null>(null);

  const act = async (label: string, fn: () => Promise<unknown>) => {
    setBusy(true);
    setNote(null);
    try {
      await fn();
      setNote(label);
      onChange();
    } catch (e) {
      setNote(`Failed: ${(e as Error).message}`);
    } finally {
      setBusy(false);
    }
  };

  return (
    <aside className="flex flex-col gap-5">
      <div className="panel rounded-[3px] p-4">
        <Label>the desk</Label>
        <h2 className="font-display text-[24px] font-semibold">Human controls</h2>
        <p className="text-[14px] text-bone-dim italic">Doppel contains; a person decides.</p>
        {session && (
          <dl className="mt-3 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 font-mono text-[12px]">
            <dt className="text-bone-dim">session</dt>
            <dd>{session.session_id}</dd>
            <dt className="text-bone-dim">tier now</dt>
            <dd>
              <TierBadge tier={session.tier} />
            </dd>
            <dt className="text-bone-dim">mirror world</dt>
            <dd>{session.decoy_mode ? "yes — real access cut" : "no"}</dd>
            <dt className="text-bone-dim">frozen</dt>
            <dd>{session.frozen ? "yes — calls return 423" : "no"}</dd>
          </dl>
        )}
      </div>

      {approvals.map((ap) => (
        <div key={ap.approval_id} className="rounded-[3px] border border-amber/60 bg-amber/5 p-4">
          <Label className="!text-amber">held for approval</Label>
          <p className="mt-1 font-mono text-[14px] text-bone">{ap.tool}</p>
          <p className="font-mono text-[12px] break-words text-bone-dim">{argLine(ap.args)}</p>
          <p className="mt-1 text-[14px] text-bone-dim italic">“{ap.purpose}”</p>
          <div className="mt-3 flex gap-2">
            <Button disabled={busy} onClick={() => act("Approved — the held call ran.", () => api.approve(ap.approval_id))}>
              approve
            </Button>
            <Button variant="blood" disabled={busy} onClick={() => act("Denied — the held call was dropped.", () => api.deny(ap.approval_id))}>
              deny
            </Button>
          </div>
        </div>
      ))}

      <div className="flex flex-col gap-2">
        <Button
          disabled={busy || !session || session.frozen}
          onClick={() => act("Frozen — further calls are refused.", () => api.freeze(alert.session_id))}
        >
          freeze session
        </Button>
        <Button variant="blood" disabled={busy || !session} onClick={() => dialog.current?.showModal()}>
          restore session…
        </Button>
        {note && <p className="font-mono text-[12px] text-amber">{note}</p>}
      </div>

      <Link to={`/locker?session=${alert.session_id}`} className="label !text-[14px] !text-amber hover:!text-parch">
        evidence locker · {captures} capture{captures === 1 ? "" : "s"} from this session →
      </Link>

      <dialog
        ref={dialog}
        className="m-auto max-w-md rounded-[3px] border border-oxblood-hi bg-desk p-6 text-bone backdrop:bg-black/70"
      >
        <Label>confirm</Label>
        <h3 className="font-display text-[26px] font-semibold">Restore this session?</h3>
        <ul className="mt-2 list-disc pl-5 text-[15px] leading-relaxed text-bone-dim">
          <li>Risk and tier reset to zero; the session leaves the mirror world.</li>
          <li>A fresh token is issued. The old one keeps working for two minutes.</li>
          {rootSource && <li>The root-cause content ({rootSource}) is quarantined.</li>}
          <li>This case file is marked resolved.</li>
        </ul>
        <div className="mt-5 flex justify-end gap-2">
          <Button onClick={() => dialog.current?.close()}>cancel</Button>
          <Button
            variant="blood"
            onClick={() => {
              dialog.current?.close();
              act("Restored — risk cleared, fresh token issued.", () => api.restore(alert.session_id));
            }}
          >
            restore
          </Button>
        </div>
      </dialog>
    </aside>
  );
}
