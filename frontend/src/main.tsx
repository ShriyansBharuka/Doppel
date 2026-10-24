import { lazy, StrictMode, Suspense, useEffect } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Route, Routes, useLocation } from "react-router-dom";
import "./index.css";
import { Waking } from "./components/Waking";
import Landing from "./pages/Landing";
import Console from "./pages/Console";
import TwoViews from "./pages/TwoViews";
import CaseFile from "./pages/CaseFile";
import Locker from "./pages/Locker";
// The two chart pages load Recharts; keep it out of the first load.
const Drift = lazy(() => import("./pages/Drift"));
const Results = lazy(() => import("./pages/Results"));

const opening = (what: string) => <p className="p-10 text-center text-bone-dim italic">Opening the {what}…</p>;

const TITLES: [RegExp, string][] = [
  [/^\/console/, "Console"],
  [/^\/scenario\//, "Two Views"],
  [/^\/case\//, "Case File"],
  [/^\/locker/, "Evidence Locker"],
  [/^\/drift/, "Slow Drift"],
  [/^\/results/, "Results"],
];

function TitleSync() {
  const { pathname } = useLocation();
  useEffect(() => {
    const page = TITLES.find(([re]) => re.test(pathname))?.[1];
    document.title = page ? `${page} · DOPPEL` : "DOPPEL — is your agent still itself?";
  }, [pathname]);
  return null;
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <BrowserRouter>
      <TitleSync />
      <Waking>
        <Routes>
          <Route path="/" element={<Landing />} />
          <Route path="/console" element={<Console />} />
          <Route path="/scenario/:runId" element={<TwoViews />} />
          <Route path="/case/:alertId" element={<CaseFile />} />
          <Route path="/locker" element={<Locker />} />
          <Route
            path="/drift"
            element={
              <Suspense fallback={opening("drift file")}>
                <Drift />
              </Suspense>
            }
          />
          <Route
            path="/results"
            element={
              <Suspense fallback={opening("verdict")}>
                <Results />
              </Suspense>
            }
          />
          <Route path="*" element={<Landing />} />
        </Routes>
      </Waking>
    </BrowserRouter>
  </StrictMode>,
);
