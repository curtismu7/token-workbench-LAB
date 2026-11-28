import React, { useEffect, useState } from "react";
import ShelfLink from "./components/ShelfLink.jsx";
import VerifyMark from "./components/VerifyMark.jsx";
import { getHealth, getInfo, getMeta, postReset, setMode } from "./lib/api.js";
import Decode from "./components/Decode.jsx";
import Tester from "./components/Tester.jsx";
import Checker from "./components/Checker.jsx";
import Flows from "./components/Flows.jsx";
import Story from "./components/Story.jsx";
import TalkTrack from "./components/TalkTrack.jsx";
import ReleaseNotes from "./components/ReleaseNotes.jsx";
import TopMenu from "./top-menu/TopMenu";
import RealStatus from "./components/RealStatus.jsx";
import { workspaceId } from "./lib/api.js";
import ReturnLink from "./return-link/ReturnLink.jsx";
import { readReturnContext } from "./return-link/returnTargets.js";
import { tabFor } from "./handoffMap.js";
import ModeModal from "./mode-modal/ModeModal.jsx";

const safe = (fn, fallback) => { try { return fn(); } catch { return fallback; } };
const initialTheme = () => {
  const t = safe(() => localStorage.getItem("tw-theme"), null);
  return ["auto", "light", "dark"].includes(t) ? t : "auto";
};

export const TABS = [["decode", "Decode / Trace"], ["tester", "Wrong-token tester"], ["checker", "Profile checker"], ["flows", "Flow catalog"], ["talk", "Talk track"]];

// The Real-or-mock modal's lines (it replaced the long MOCK / REAL / hosted banners). Hosted keeps its own client-side line; the server's `banner` field in /api/meta is left alone.
export const MODE_LINES = {
  mock: "Every authorization server, resource server and token here is a stub in this process on loopback. Nothing real is contacted.",
  hosted: "HOSTED SIMULATION: this is a shared hosted demo. Every stub server, key and token here is simulated and lives in memory in the server, private to your browser tab. Nothing real is contacted and you cannot point it at anything.",
};
export const realLine = (origin) => `Decode / Trace and the Profile checker call the configured issuer ${origin || "(not named)"} and nothing else, and the tokens shown are real, raw on purpose: treat this screen as sensitive. The tester and the flow catalog still use the in-process stubs.`;

// Real mode on a tab that has no Real version: say so, every time.
const StubsOnly = () => <p className="callout-text" data-testid="real-note">No Real version of this tab: it always runs against the in-process stubs, so its results are MOCK even while the header says Real.</p>;

export default function App() {
  const [theme, setTheme] = useState(initialTheme);
  // Opened from Customer Agent LAB: open the mapped tab (handoffMap.js), once, on load.
  const [tab, setTab] = useState(() => tabFor(readReturnContext(window.location.search)) || "decode");
  const [health, setHealth] = useState(null);
  const [message, setMessage] = useState("");
  const [hosted, setHosted] = useState(false);
  const [metaDone, setMetaDone] = useState(false);
  const [infoDone, setInfoDone] = useState(false);
  const [info, setInfo] = useState(null);
  const [notesOpen, setNotesOpen] = useState(false);

  useEffect(() => {
    if (theme === "auto") document.documentElement.removeAttribute("data-theme");
    else document.documentElement.setAttribute("data-theme", theme);
    safe(() => localStorage.setItem("tw-theme", theme));
  }, [theme]);
  // The hosted build (MODE=se-mock) says so in /api/meta; the local build does not. The modal waits for it (and for /api/info) so a hosted or Real page never flashes the wrong line.
  useEffect(() => { getMeta().then((m) => setHosted(m?.hosted === true), () => {}).finally(() => setMetaDone(true)); }, []);
  useEffect(() => { getHealth().then(setHealth, () => setHealth({ unreachable: true })); }, []);
  useEffect(() => { getInfo().then(setInfo, () => {}).finally(() => setInfoDone(true)); }, []);
  // Rule 19: the Mock/Real toggle. A switch is announced and the server's answer is what the toggle shows; every tab is
  // keyed on the mode, so it reloads its data after a switch.
  const onSelectMode = async (source) => {
    try { setInfo(await setMode(source)); setMessage(`Mode: ${source === "real" ? "Real" : "Mock"}.`); } catch (e) { setMessage(e.message); }
  };
  // Reset (rule 3): the server drops every non-default workspace's runtime state; the tabs re-key on the source.
  const onReset = async () => {
    try { const r = await postReset(); setMessage(r?.note ? `Reset: ${r.note}` : "Reset: the lab's runtime state is back to defaults."); } catch (e) { setMessage(e.message); }
  };

  const real = info?.source === "real";
  const key = info?.source || "mock";
  return (
    <>
      <a className="skip" href="#main" onClick={(e) => { e.preventDefault(); document.getElementById("main")?.focus(); }}>Skip to content</a>
      {health?.unreachable && <div className="banner warn" role="alert">Cannot reach the Token Workbench API. Is the server running?</div>}
      {health && !health.unreachable && health.state !== "ready" && <div className="banner warn" role="alert">Server health is {health.state}. Run <code>npm run doctor</code>.</div>}
      <ReturnLink app="token-workbench" />
      <header className="shell-bar">
        <span className="shell-brand">
          <span className="shell-logo" aria-hidden="true">TW</span>
          <h1>Token Workbench</h1>
          {real
            ? <span className="mode mode--real" data-testid="mode-badge">REAL<span className="sr-only">: calls go to the configured issuer</span></span>
            : <span className="mode mode--demo" data-testid="mode-badge">DEMO<span className="sr-only">: stub servers on loopback, nothing real is contacted</span></span>}
        </span>
        <nav className="tabbar shell-nav" aria-label="Tools">
          {TABS.map(([id, label]) => (
            <button key={id} type="button" className="tab" aria-pressed={tab === id} aria-current={tab === id ? "page" : undefined} onClick={() => { setTab(id); setMessage(""); }}>{label}</button>
          ))}
        </nav>
        <span className="shell-right">
          <TopMenu
          postman={{ repo: "curtismu7/token-workbench-LAB", slug: "token-workbench-lab" }}
          mode={{ value: real ? "real" : "mock", onChange: onSelectMode, realAvailable: info ? info.realAvailable === true : null, realHint: info && !info.realAvailable ? "Real is not configured. Set TW_REAL, TW_REAL_CLIENT_SECRET in the .env file beside docker-compose.yml, then restart the lab." : undefined }}
          theme={{ value: theme, onChange: setTheme }}
          help={{ href: "https://github.com/curtismu7/token-workbench-LAB#readme" }}
          version={info?.version || null}
          onVersion={() => setNotesOpen(true)}
          onReset={onReset}
          talkTrack={{ active: tab === "talk", onToggle: () => { setTab("talk"); setMessage(""); } }}
        >
          <ShelfLink headers={() => ({ "X-Workspace-Id": workspaceId() })} />
          <VerifyMark id="token-workbench" headers={() => ({ "X-Workspace-Id": workspaceId() })} />
          <ReturnLink app="token-workbench" variant="header" />
        </TopMenu>
        </span>
      </header>
      <main id="main" tabIndex={-1} className="page">
        <div role="status" aria-live="polite" className="live" data-testid="live">{message}</div>
        <RealStatus info={info} />
        <div hidden={tab !== "decode"}><Decode key={key} source={key} announce={setMessage} signinProviders={info?.real?.signin?.providers || []} /></div>
        <div hidden={tab !== "tester"}>{real && <StubsOnly />}<Tester key={key} announce={setMessage} /></div>
        <div hidden={tab !== "checker"}><Checker key={key} source={key} issuer={info?.real?.issuer} announce={setMessage} /></div>
        {tab === "flows" && <>{real && <StubsOnly />}<Flows theme={theme} announce={setMessage} /></>}
        {tab === "talk" && <TalkTrack />}
        {notesOpen && <ReleaseNotes version={info?.version || ""} onClose={() => setNotesOpen(false)} />}
        <Story active={tab} />
      </main>
      <ModeModal
        mode={real && !hosted ? "real" : "mock"}
        lines={{ mock: hosted ? MODE_LINES.hosted : MODE_LINES.mock, real: realLine(info?.real?.issuerOrigin) }}
        suppress={!(metaDone && infoDone)}
        storageKey={hosted ? "tw-mode-hosted" : "tw-mode"}
      />
    </>
  );
}
