import React, { useEffect, useState } from "react";
import ShelfLink from "./components/ShelfLink.jsx";
import { getHealth, getInfo, getMeta, setMode } from "./lib/api.js";
import Decode from "./components/Decode.jsx";
import Tester from "./components/Tester.jsx";
import Checker from "./components/Checker.jsx";
import Flows from "./components/Flows.jsx";
import Story from "./components/Story.jsx";
import ModeToggle from "./components/ModeToggle.jsx";
import RealStatus from "./components/RealStatus.jsx";
import { workspaceId } from "./lib/api.js";
import ReturnLink from "./return-link/ReturnLink.jsx";
import { readReturnContext } from "./return-link/returnTargets.js";
import { tabFor } from "./handoffMap.js";

const safe = (fn, fallback) => { try { return fn(); } catch { return fallback; } };
const initialTheme = () => {
  const t = safe(() => localStorage.getItem("tw-theme"), null);
  return ["auto", "light", "dark"].includes(t) ? t : "auto";
};

export const TABS = [["decode", "Decode / Trace"], ["tester", "Wrong-token tester"], ["checker", "Profile checker"], ["flows", "Flow catalog"]];

// Real mode on a tab that has no Real version: say so, every time.
const StubsOnly = () => <p className="callout-text" data-testid="real-note">No Real version of this tab: it always runs against the in-process stubs, so its results are MOCK even while the header says Real.</p>;

export default function App() {
  const [theme, setTheme] = useState(initialTheme);
  // Opened from Customer Agent LAB: open the mapped tab (handoffMap.js), once, on load.
  const [tab, setTab] = useState(() => tabFor(readReturnContext(window.location.search)) || "decode");
  const [health, setHealth] = useState(null);
  const [message, setMessage] = useState("");
  const [hostedBanner, setHostedBanner] = useState(null);
  const [info, setInfo] = useState(null);

  useEffect(() => {
    if (theme === "auto") document.documentElement.removeAttribute("data-theme");
    else document.documentElement.setAttribute("data-theme", theme);
    safe(() => localStorage.setItem("tw-theme", theme));
  }, [theme]);
  // The hosted build (MODE=se-mock) serves its banner text in /api/meta; the local build serves none.
  useEffect(() => { getMeta().then((m) => setHostedBanner(m?.hosted && typeof m.banner === "string" ? m.banner : null), () => {}); }, []);
  useEffect(() => { getHealth().then(setHealth, () => setHealth({ unreachable: true })); }, []);
  useEffect(() => { getInfo().then(setInfo, () => {}); }, []);
  // Rule 19: the Mock/Real toggle. A switch is announced and the server's answer is what the toggle shows; every tab is
  // keyed on the mode, so it reloads its data after a switch.
  const onSelectMode = async (source) => {
    try { setInfo(await setMode(source)); setMessage(`Mode: ${source === "real" ? "Real" : "Mock"}.`); } catch (e) { setMessage(e.message); }
  };

  const real = info?.source === "real";
  const key = info?.source || "mock";
  return (
    <>
      <a className="skip" href="#main" onClick={(e) => { e.preventDefault(); document.getElementById("main")?.focus(); }}>Skip to content</a>
      {!hostedBanner && (real
        ? <div className="banner" role="note" data-state="live" data-testid="mode-banner">REAL: Decode / Trace and the Profile checker call the configured issuer {info.real?.issuerOrigin} and nothing else. Tokens shown are real, raw on purpose: treat this screen as sensitive. The tester and the flow catalog still use the in-process stubs.</div>
        : <div className="banner" role="note" data-testid="mode-banner">MOCK: every authorization server, resource server and token here is a stub in this process on loopback. Nothing real is contacted.</div>)}
      {health?.unreachable && <div className="banner warn" role="alert">Cannot reach the Token Workbench API. Is the server running?</div>}
      {health && !health.unreachable && health.state !== "ready" && <div className="banner warn" role="alert">Server health is {health.state}. Run <code>npm run doctor</code>.</div>}
      {hostedBanner && <div className="banner hosted" role="note" data-testid="hosted-banner">{hostedBanner}</div>}
      <ReturnLink app="token-workbench" />
      <header className="top">
        <h1>Token Workbench</h1>
        <ShelfLink headers={() => ({ "X-Workspace-Id": workspaceId() })} />
        <ReturnLink app="token-workbench" variant="header" />
        {real
          ? <span className="mode mode--real" data-testid="mode-badge">REAL<span className="sr-only">: calls go to the configured issuer</span></span>
          : <span className="mode mode--demo" data-testid="mode-badge">DEMO<span className="sr-only">: stub servers on loopback, nothing real is contacted</span></span>}
        <ModeToggle info={info} onSelect={onSelectMode} />
        <nav aria-label="Tools">
          {TABS.map(([id, label]) => (
            <button key={id} type="button" className="tab" aria-pressed={tab === id} onClick={() => { setTab(id); setMessage(""); }}>{label}</button>
          ))}
        </nav>
        <label className="inline">Theme
          <select value={theme} onChange={(e) => setTheme(e.target.value)} data-testid="theme">
            <option value="auto">Auto</option>
            <option value="light">Light</option>
            <option value="dark">Dark</option>
          </select>
        </label>
      </header>
      <main id="main" tabIndex={-1} className="page">
        <div role="status" aria-live="polite" className="live" data-testid="live">{message}</div>
        <RealStatus info={info} />
        <div hidden={tab !== "decode"}><Decode key={key} source={key} announce={setMessage} /></div>
        <div hidden={tab !== "tester"}>{real && <StubsOnly />}<Tester key={key} announce={setMessage} /></div>
        <div hidden={tab !== "checker"}><Checker key={key} source={key} issuer={info?.real?.issuer} announce={setMessage} /></div>
        {tab === "flows" && <>{real && <StubsOnly />}<Flows theme={theme} announce={setMessage} /></>}
        <Story active={tab} />
      </main>
    </>
  );
}
