import React, { useCallback, useEffect, useMemo, useState } from "react";
import { Background, Controls, Handle, MarkerType, Position, ReactFlow } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { ArrowNoLabel, EdgeLabels, FitOpen, Passport, PassportActions } from "../diagram-kit/DiagramKit.jsx";
import { boxPassport, sidePoint } from "../diagram-kit/diagramKit.js";
import "../diagram-kit/diagram-kit.css";
import { getFlowCompare, postFlowRun } from "../lib/api.js";
import Badge from "./Badge.jsx";

// Five actors, boxes you can drag. Each step of the selected flow is an arrow between two actors.
const ACTORS = {
  client: "Client app", browser: "Browser", as: "Authorization server", rs: "Resource server", attacker: "Attacker",
};
const START = [
  { id: "client", position: { x: 0, y: 130 } },
  { id: "browser", position: { x: 280, y: 0 } },
  { id: "as", position: { x: 560, y: 130 } },
  { id: "rs", position: { x: 840, y: 130 } },
  { id: "attacker", position: { x: 560, y: 290 } },
].map((n) => ({ ...n, type: "actor", data: { title: ACTORS[n.id] } }));
const SPEEDS = [["0.5", "0.5x"], ["1", "1x"], ["2", "2x"], ["4", "4x"]];
const BASE_MS = 1700;

function Actor({ data }) {
  return (
    <div className={`fbox${data.on ? " on" : ""}${data.dim ? " dim" : ""}${data.evil ? " evil" : ""}`}>
      <Handle id="t" type="target" position={Position.Left} />
      <Handle id="s" type="source" position={Position.Right} />
      <strong>{data.title}</strong>
      {data.tag && <span>{data.tag}</span>}
      {data.passport && <Passport p={data.passport} />}
    </div>
  );
}

// The curve only: every label is drawn by the diagram kit's EdgeLabels, in a layer above the boxes,
// placed so no two labels overlap and none sits on a box (the shared standard, UI patterns §8c).
function StepEdge(props) {
  return <ArrowNoLabel {...props} className={`step-edge ${props.data?.state ?? "idle"}${props.data?.evil ? " evil" : ""}`} />;
}
const nodeTypes = { actor: Actor };
const edgeTypes = { step: StepEdge };

const OUTCOME = { attack_succeeds: ["deny", "ATTACK SUCCEEDS"], attack_blocked: ["ok", "ATTACK BLOCKED"] };

function Side({ title, run, kind }) {
  if (!run) return <div className="card side"><h3>{title}</h3><p className="muted">Loading</p></div>;
  const [k, word] = OUTCOME[run.attack.outcome];
  return (
    <div className="card side" data-testid={`side-${kind}`}>
      <h3>{title}</h3>
      <ol className="steps">{run.steps.map((s) => <li key={s.n} className={s.evil ? "evil" : ""}><span className="who">{ACTORS[s.from]} to {ACTORS[s.to]}</span> {s.label}{s.evil && <> <Badge kind="deny">attacker</Badge></>}</li>)}</ol>
      <p><Badge kind={k}>{word}</Badge> {run.attack.reason}</p>
    </div>
  );
}

export default function Flows({ theme, announce }) {
  const [compare, setCompare] = useState(null);
  const [mech, setMech] = useState("dpop");
  const [prot, setProt] = useState(true);
  const [runs, setRuns] = useState({});
  const [error, setError] = useState("");
  const [moved, setMoved] = useState(START);
  const [speed, setSpeed] = useState("1");
  const [step, setStep] = useState(-1);
  const [running, setRunning] = useState(false);

  useEffect(() => { getFlowCompare().then(setCompare, (e) => setError(e.message)); }, []);
  useEffect(() => {
    let live = true;
    setRuns({}); setStep(-1); setRunning(false);
    Promise.all([postFlowRun(mech, false), postFlowRun(mech, true)]).then(([off, on]) => { if (live) setRuns({ off, on }); }, (e) => { if (live) setError(e.message); });
    return () => { live = false; };
  }, [mech]);

  const cur = runs[prot ? "on" : "off"];
  const steps = cur?.steps ?? [];

  useEffect(() => {
    if (!running) return undefined;
    if (step >= steps.length) { setRunning(false); return undefined; }
    const t = setTimeout(() => setStep((s) => s + 1), BASE_MS / Number(speed));
    return () => clearTimeout(t);
  }, [running, step, steps.length, speed]);

  const simulate = () => { if (!cur || running) return; setStep(0); setRunning(true); announce(`Simulating ${cur.mechanism.name} ${prot ? "with" : "without"} protection.`); };
  const reset = () => { setRunning(false); setStep(-1); setOpen(null); setMoved(START); announce("Diagram reset."); };
  const onNodesChange = useCallback((c) => setMoved((n) => n.map((x) => { const ch = c.find((y) => y.id === x.id); return ch?.position ? { ...x, position: ch.position } : x; })), []);

  // Click a box and it expands in place with its details (the shared diagram kit's Passport, §8c).
  const [open, setOpen] = useState(null);
  const graph = useMemo(() => ({
    nodes: START.map((n) => ({ id: n.id, label: ACTORS[n.id], group: n.id === "attacker" ? "attacker" : "actor" })),
    edges: steps.map((s) => ({ source: s.from, target: s.to, label: `${s.n}. ${s.label}` })),
    groups: { actor: { label: "Actor" }, attacker: { label: "Attacker" } },
  }), [steps]);
  const passportFor = useMemo(() => (nid) => boxPassport(graph, nid), [graph]);

  const done = step >= steps.length && steps.length > 0;
  const now = step >= 0 && step < steps.length ? steps[step] : null;
  const nodes = useMemo(() => moved.map((n) => {
    const active = now && (now.from === n.id || now.to === n.id);
    return { ...n, ariaLabel: n.data.title, zIndex: n.id === open ? 10 : undefined, className: n.id === open ? "dk-open" : undefined,
      data: { ...n.data, on: !!active, dim: !!now && !active, evil: n.id === "attacker", tag: done && cur && n.id === "attacker" ? (cur.attack.outcome === "attack_blocked" ? "blocked" : "succeeded") : undefined,
        passport: n.id === open ? passportFor(n.id) : null } };
  }), [moved, now, done, cur, open, passportFor]);
  const edges = useMemo(() => steps.filter((s) => s.from !== s.to).map((s) => ({
    id: `s${s.n}`, source: s.from, target: s.to, type: "step", sourceHandle: "s", targetHandle: "t",
    markerEnd: { type: MarkerType.ArrowClosed },
    data: { n: s.n, evil: s.evil, state: step < 0 ? "idle" : s.n - 1 === step ? "now" : s.n - 1 < step ? "past" : "future" },
  })), [steps, step]);
  // One label item per arrow, for the kit's EdgeLabels layer: the arrows run left to right on the facing sides.
  const items = useMemo(() => steps.filter((s) => s.from !== s.to).map((s) => ({
    id: `s${s.n}`, text: `${s.n}. ${s.label}`, source: s.from, target: s.to, sourceHandle: "r", targetHandle: "l",
    active: step >= 0 && s.n - 1 === step, dim: step >= 0 && s.n - 1 !== step,
  })), [steps, step]);
  const labelPointFor = useCallback((box, handle) => sidePoint(box, handle === "s" ? "r" : "l"), []);
  const actions = useMemo(() => ({
    open: (nid) => setOpen(nid),
    close: () => setOpen(null),
    link: (nid) => { const u = new URL(window.location.href); u.searchParams.set("box", nid); return u.toString(); },
  }), []);

  const caption = !cur ? "Loading." : now ? `Step ${now.n} of ${steps.length}: ${ACTORS[now.from]} to ${ACTORS[now.to]}: ${now.label}`
    : done ? `${cur.attack.outcome === "attack_blocked" ? "Attack blocked" : "Attack succeeded"}: ${cur.attack.reason}` : "Press Simulate to walk the flow step by step.";

  return (
    <section aria-labelledby="h-flows">
      <div className="row"><h2 id="h-flows">Token-flow catalog</h2><Badge kind="info" title="Computed in memory; no real server is involved">SIMULATION</Badge></div>
      <p className="lede">Six mechanisms, each shown with and without its protection against the one attack it stops. The keys, hashes and signatures are really computed in memory, but there is no network and no real authorization server: this illustrates the mechanisms and says nothing about how any product behaves.</p>
      {error && <p className="alert" role="alert">{error}</p>}
      {cur && <p className="note"><strong>Limits of {cur.mechanism.name}:</strong> {cur.mechanism.limits}</p>}
      <div className="card controls">
        <label>Mechanism{" "}
          <select value={mech} onChange={(e) => setMech(e.target.value)}>{(compare?.rows ?? [{ id: mech, name: mech.toUpperCase() }]).map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}</select>
        </label>
        <label className="check"><input type="checkbox" checked={prot} onChange={(e) => { setProt(e.target.checked); setStep(-1); setRunning(false); }} /> With {cur?.mechanism.name ?? "protection"}</label>
        <label>Speed{" "}
          <select value={speed} onChange={(e) => setSpeed(e.target.value)}>{SPEEDS.map(([v, t]) => <option key={v} value={v}>{t}</option>)}</select>
        </label>
        <button type="button" className="btn primary" onClick={simulate} aria-disabled={running || !cur}>Simulate</button>
        <button type="button" className="btn" onClick={reset}>Reset</button>
        <span className="muted small">Drag any box.</span>
      </div>
      <div className="flow-scroll" tabIndex={0} role="region" aria-label="Diagram area (scrollable on narrow screens)">
      <div className="flow-wrap" role="group" aria-label={`${cur?.mechanism.name ?? ""} flow diagram between client, browser, authorization server, resource server and attacker. Boxes can be dragged. The steps are listed below.`}>
        <PassportActions.Provider value={actions}>
          <ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} edgeTypes={edgeTypes} onNodesChange={onNodesChange} colorMode={theme}
            onNodeClick={(_, n) => setOpen((o) => (o === n.id ? null : n.id))} onPaneClick={() => setOpen(null)}
            fitView fitViewOptions={{ padding: 0.1 }} nodesConnectable={false} proOptions={{ hideAttribution: true }} minZoom={0.2}>
            <Background />
            <Controls showInteractive={false} />
            <EdgeLabels items={items} pointFor={labelPointFor} fallback={{ w: 160, h: 60 }} />
            <FitOpen open={open} closePadding={0.1} />
          </ReactFlow>
        </PassportActions.Provider>
      </div>
      </div>
      <p className="caption" role="status" aria-live="polite" data-testid="caption">{caption}</p>
      <div className="sides">
        <Side title="Without protection" run={runs.off} kind="off" />
        <Side title={`With ${cur?.mechanism.name ?? "protection"}`} run={runs.on} kind="on" />
      </div>
      {compare && (
        <div className="card table-wrap" tabIndex={0} role="region" aria-label="Mechanism comparison (scrollable)">
          <table data-testid="compare">
            <caption className="sr-only">Each mechanism with and without protection</caption>
            <thead><tr><th scope="col">Mechanism</th><th scope="col">Attack it stops</th><th scope="col">Without</th><th scope="col">With</th></tr></thead>
            <tbody>
              {compare.rows.map((r) => (
                <tr key={r.id} className={r.id === mech ? "sel" : ""}>
                  <th scope="row"><button type="button" className="link" aria-pressed={r.id === mech} onClick={() => setMech(r.id)}>{r.name}</button><br /><span className="muted small">{r.rfc}</span></th>
                  <td><span className="small"><strong>{r.attack.title}.</strong> {r.adds}</span></td>
                  <td><Badge kind={OUTCOME[r.without.outcome][0]}>{OUTCOME[r.without.outcome][1]}</Badge></td>
                  <td><Badge kind={OUTCOME[r.with.outcome][0]}>{OUTCOME[r.with.outcome][1]}</Badge></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
