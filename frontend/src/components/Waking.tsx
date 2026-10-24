import { useEffect, useState, type ReactNode } from "react";
import { motion } from "framer-motion";
import { api } from "../api";
import { Label } from "./ui";

/** Holds the app until /health answers. Render's free tier takes up to ~50 s to wake. */
export function Waking({ children }: { children: ReactNode }) {
  const [ready, setReady] = useState(false);
  const [showLoader, setShowLoader] = useState(false);
  const [elapsed, setElapsed] = useState(0);

  useEffect(() => {
    let stop = false;
    const started = Date.now();
    const loaderTimer = setTimeout(() => setShowLoader(true), 400); // no flash when the server is warm
    const tick = setInterval(() => setElapsed(Math.round((Date.now() - started) / 1000)), 1000);
    (async () => {
      while (!stop) {
        try {
          await api.health();
          if (!stop) setReady(true);
          return;
        } catch {
          await new Promise((r) => setTimeout(r, 2500));
        }
      }
    })();
    return () => {
      stop = true;
      clearTimeout(loaderTimer);
      clearInterval(tick);
    };
  }, []);

  if (ready) return <>{children}</>;
  if (!showLoader) return null;

  return (
    <div className="flex min-h-screen flex-col items-center justify-center gap-8 px-6 text-center">
      <motion.svg
        viewBox="0 0 120 120"
        className="h-28 w-28"
        animate={{ scale: [1, 1.04, 1] }}
        transition={{ duration: 3.2, repeat: Infinity, ease: "easeInOut" }}
        aria-hidden
      >
        <path
          d="M60 6c9 0 12 6 20 9s15 1 20 8 1 14 4 21 9 10 9 16-6 10-9 17 1 14-4 21-13 5-20 8-11 9-20 9-12-6-20-9-15-1-20-8-1-14-4-21-9-10-9-17 6-9 9-16-1-14 4-21 13-5 20-8 11-9 20-9z"
          fill="var(--color-oxblood)"
        />
        <circle cx="60" cy="60" r="36" fill="none" stroke="var(--color-oxblood-hi)" strokeWidth="2" />
        <text x="60" y="76" textAnchor="middle" fontFamily="Cormorant Garamond, serif" fontSize="46" fontWeight="700" fill="#e9d9b0" opacity="0.85">
          D
        </text>
        <motion.path
          d="M60 22 L56 44 L64 52 L58 72"
          fill="none"
          stroke="var(--color-ink)"
          strokeWidth="1.6"
          initial={{ pathLength: 0 }}
          animate={{ pathLength: [0, 1, 1, 0] }}
          transition={{ duration: 4, repeat: Infinity, ease: "easeInOut" }}
        />
      </motion.svg>
      <div>
        <h1 className="font-display text-4xl font-semibold text-bone candle">Breaking the seal…</h1>
        <p className="mt-3 max-w-md text-bone-dim">
          Waking the server — this can take up to a minute. The free host sleeps when no one is watching.
        </p>
      </div>
      <Label>{elapsed} s elapsed</Label>
    </div>
  );
}
