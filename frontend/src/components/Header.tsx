import type { ReactNode } from "react";
import { Link, NavLink } from "react-router-dom";
import { Label, Wordmark } from "./ui";

const NAV = [
  ["/console", "Console"],
  ["/locker", "Evidence Locker"],
  ["/drift", "Drift"],
  ["/results", "Results"],
] as const;

export function Header({ right }: { right?: ReactNode }) {
  return (
    <header className="flex flex-wrap items-center gap-x-8 gap-y-3 border-b border-line px-4 py-3 lg:px-6">
      <Link to="/" className="flex items-baseline gap-3 pb-1">
        <Wordmark size={24} mirror={false} />
        <Label className="hidden sm:inline">case / doppel</Label>
      </Link>
      <nav className="flex gap-5">
        {NAV.map(([to, name]) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              `font-label text-[16px] font-semibold tracking-[0.12em] lowercase [font-variant:small-caps] transition-colors ${
                isActive ? "text-amber" : "text-bone-dim hover:text-bone"
              }`
            }
          >
            {name}
          </NavLink>
        ))}
      </nav>
      <div className="ml-auto flex flex-wrap items-center gap-4">{right}</div>
    </header>
  );
}
