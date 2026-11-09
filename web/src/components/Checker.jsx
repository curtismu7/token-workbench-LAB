import React, { useEffect, useState } from "react";
import { getMeta, postCheckerRun } from "../lib/api.js";
import Badge from "./Badge.jsx";
import Trace from "./Trace.jsx";

const KIND = { pass: ["ok", "PASS"], fail: ["deny", "FAIL"], error: ["hold", "ERROR"], not_checked: ["mute", "NOT CHECKED"] };

function Pack({ id, pack }) {
  const counts = pack.rules.reduce((a, r) => ({ ...a, [r.status]: (a[r.status] || 0) + 1 }), {});
  return (
    <div className="card" data-testid={`pack-${id}`}>
      <div className="row">
        <h3>{pack.title}</h3>
        {pack.unverified && <Badge kind="hold" title="The rule pack has not been checked against the profile text">UNVERIFIED</Badge>}
        <span className="muted small">{counts.pass || 0} pass, {counts.fail || 0} fail{counts.error ? `, ${counts.error} error` : ""}{counts.not_checked ? `, ${counts.not_checked} not checked` : ""}</span>
      </div>
      {pack.unverified && <p className="callout-text" data-testid="fapi-note">{pack.note}</p>}
      {!pack.unverified && pack.note && <p className="muted small" data-testid="bcp-note">{pack.note}</p>}
      <div className="table-wrap" tabIndex={0} role="region" aria-label={`${pack.title} results (scrollable)`}>
        <table>
          <caption className="sr-only">{pack.title}: result per rule with the evidence</caption>
          <thead><tr><th scope="col">Rule</th><th scope="col">Result</th><th scope="col">Evidence</th></tr></thead>
          <tbody>
            {pack.rules.map((r) => (
              <tr key={r.id} data-rule={r.id}>
                <th scope="row">{r.title}<br /><span className="muted small">{r.rfc}</span></th>
                <td><Badge kind={KIND[r.status][0]}>{KIND[r.status][1]}</Badge></td>
                <td><span className="small">{r.evidence}</span><details><summary>Why it matters</summary><p>{r.why}</p></details></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// source "real": the configured issuer's published metadata only (one GET); no stub choice, no typed URL.
export default function Checker({ announce, source = "mock", issuer }) {
  const real = source === "real";
  const [profiles, setProfiles] = useState([]);
  const [hosted, setHosted] = useState(false);
  const [choice, setChoice] = useState("good");
  const [url, setUrl] = useState("");
  const [pack, setPack] = useState("both");
  const [res, setRes] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [trace, setTrace] = useState(null);

  useEffect(() => { getMeta().then((m) => { setProfiles(m.profiles); setHosted(!!m.hosted); }, (e) => setError(e.message)); }, []);

  const run = async () => {
    setBusy(true); setError(""); announce("Running"); setTrace(null);
    try {
      const d = await postCheckerRun(real ? { pack } : { ...(choice === "url" ? { target: url.trim() } : { profile: choice }), pack });
      setRes(d); setTrace(d.trace || null);
      const part = ([id, p]) => `${id === "fapi" ? "FAPI 2.0 pack (UNVERIFIED)" : "RFC 9700 pack"}: ${p.rules.filter((r) => r.status === "pass").length} passed, ${p.rules.filter((r) => r.status === "fail").length} failed`;
      announce(`Profile checker. ${Object.entries(d.packs).map(part).join(". ")}.`);
    } catch (e) { setRes(null); setTrace(e.data?.trace || null); setError(e.status === 429 ? "Another run is in progress. Try again in a moment." : e.message); announce(""); } finally { setBusy(false); }
  };

  return (
    <section aria-labelledby="h-checker">
      <h2 id="h-checker">OAuth profile checker</h2>
      {real ? (
        <p className="lede" data-testid="checker-real">REAL: reads the published metadata of the configured issuer{issuer ? ` (${issuer})` : ""} with one GET and judges both packs from it. Rules that need active probes (crafted authorization and token requests) are NOT CHECKED: this lab never sends them to a real issuer. A PASS here means "advertised", not "enforced".</p>
      ) : <p className="lede">Pick one of the five stub authorization servers{hosted ? "" : ", or a loopback URL you started yourself,"} and probe it against an RFC 9700 pack and a simplified FAPI 2.0 pack. No credentials are sent and {hosted ? "only the simulated stub servers in this hosted demo are probed." : "nothing leaves this machine."}</p>}
      <div className="card">
        {!real && <fieldset>
          <legend>Target</legend>
          {profiles.map((p) => (
            <label key={p.id} className="radio"><input type="radio" name="target" value={p.id} checked={choice === p.id} onChange={() => setChoice(p.id)} />
              <span><strong>{p.title}</strong><br /><span className="muted small">{p.blurb}</span></span></label>
          ))}
          {!hosted && <label className="radio"><input type="radio" name="target" value="url" checked={choice === "url"} onChange={() => setChoice("url")} />
            <span><strong>A loopback URL</strong><br /><span className="muted small">http://127.0.0.1:PORT or http://localhost:PORT only. Anything else is refused.</span></span></label>}
          {!hosted && choice === "url" && (
            <div><label htmlFor="turl" className="lbl">Loopback URL</label><input id="turl" className="mono" type="text" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="http://127.0.0.1:5999" spellCheck={false} autoComplete="off" /></div>
          )}
        </fieldset>}
        <div className="row">
          <label>Rule pack{" "}
            <select value={pack} onChange={(e) => setPack(e.target.value)}>
              <option value="both">Both packs</option><option value="bcp">RFC 9700 BCP only</option><option value="fapi">FAPI 2.0 only (UNVERIFIED)</option>
            </select>
          </label>
          <button type="button" className="btn primary" onClick={run} disabled={busy || (!real && choice === "url" && !url.trim())}>{real ? "Check the issuer's metadata" : "Run checker"}</button>
        </div>
      </div>
      {error && <p className="alert" role="alert">{error}</p>}
      <Trace entries={trace} />
      {res && (
        <div data-testid="checker-result">
          <p className="muted small">Target {res.target}. {res.unreachable ? "The target did not answer, so no rule was judged." : `Metadata ${res.metadata?.found ? "found" : "not found; default endpoints were used"}.`}</p>
          {res.packs.bcp && <Pack id="bcp" pack={res.packs.bcp} />}
          {res.packs.fapi && <Pack id="fapi" pack={res.packs.fapi} />}
        </div>
      )}
    </section>
  );
}
