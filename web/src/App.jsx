import React, { useEffect, useState } from "react";
import ShelfLink from "./components/ShelfLink.jsx";
import { getHealth, getInfo, getMeta, setMode } from "./lib/api.js";
import Decode from "./components/Decode.jsx";
import Tester from "./components/Tester.jsx";
import Checker from "./components/Checker.jsx";
import Flows from "./components/Flows.jsx";
import Story from "./components/Story.jsx";
import ModeToggle from "./components/ModeToggle.jsx";
import { workspaceId } from "./lib/api.js";

const safe = (fn, fallback) => { try { return fn(); } catch { return fallback; } };
const initialTheme = () => safe(() => localStorage.getItem("tw-theme"), null)
  || (safe(() => window.matchMedia("(prefers-color-scheme: dark)").matches, false) ? "dark" : "light");

export const TABS = [["decode", "Decode / Trace"], ["tester", "Wrong-token tester"], ["checker", "Profile checker"], ["flows", "Flow catalog"]];

export default function App() {
  const [theme, setTheme] = useState(initialTheme);
  const [tab, setTab] = useState("decode");
  const [health, setHealth] = useState(null);
  const [message, setMessage] = useState("");
  const [hostedBanner, setHostedBanner] = useState(null);
  const [info, setInfo] = useState(null);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    safe(() => localStorage.setItem("tw-theme", theme));
  }, [theme]);
  // The hosted build (MODE=se-mock) serves its banner text in /api/meta; the local build serves none.
  useEffect(() => { getMeta().then((m) => setHostedBanner(m?.hosted && typeof m.banner === "string" ? m.banner : null), () => {}); }, []);
  useEffect(() => { getHealth().then(setHealth, () => setHealth({ unreachable: true })); }, []);
  useEffect(() => { getInfo().then(setInfo, () => {}); }, []);
  // Rule 19: the Mock/Real toggle. A switch is announced and the server's answer is what the toggle shows.
  const onSelectMode = async (source) => {
    try { setInfo(await setMode(source)); setMessage(`Mode: ${source === "real" ? "Real" : "Mock"}.`); } catch (e) { setMessage(e.message); }
  };

  const dark = theme === "dark";
  return (
    <>
      <a className="skip" href="#main" onClick={(e) => { e.preventDefault(); document.getElementById("main")?.focus(); }}>Skip to content</a>
      {health?.unreachable && <div className="banner warn" role="alert">Cannot reach the Token Workbench API. Is the server running?</div>}
      {health && !health.unreachable && health.state !== "ready" && <div className="banner warn" role="alert">Server health is {health.state}. Run <code>npm run doctor</code>.</div>}
      {hostedBanner && <div className="banner hosted" role="note" data-testid="hosted-banner">{hostedBanner}</div>}
      <header className="top">
        <h1>Token Workbench</h1>
        <ShelfLink headers={() => ({ "X-Workspace-Id": workspaceId() })} />
        <span className="mode mode--demo" data-testid="mode-badge">DEMO<span className="sr-only">: stub servers on loopback, nothing real is contacted</span></span>
        <ModeToggle info={info} onSelect={onSelectMode} />
        <nav aria-label="Tools">
          {TABS.map(([id, label]) => (
            <button key={id} type="button" className="tab" aria-pressed={tab === id} onClick={() => { setTab(id); setMessage(""); }}>{label}</button>
          ))}
        </nav>
        <button type="button" className="btn" onClick={() => setTheme(dark ? "light" : "dark")} aria-label={`Switch to ${dark ? "light" : "dark"} theme`}>{dark ? "Light" : "Dark"}</button>
      </header>
      <main id="main" tabIndex={-1} className="page">
        <div role="status" aria-live="polite" className="live" data-testid="live">{message}</div>
        <div hidden={tab !== "decode"}><Decode announce={setMessage} /></div>
        <div hidden={tab !== "tester"}><Tester announce={setMessage} /></div>
        <div hidden={tab !== "checker"}><Checker announce={setMessage} /></div>
        {tab === "flows" && <Flows theme={theme} announce={setMessage} />}
        <Story active={tab} />
      </main>
    </>
  );
}
