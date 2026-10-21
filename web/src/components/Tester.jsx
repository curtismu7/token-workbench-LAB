import React, { useEffect, useState } from "react";
import { getTesterCases, postTesterRun } from "../lib/api.js";
import Badge from "./Badge.jsx";

const expectText = (e) => [e.status, e.error, e.failed && `rejected by: ${e.failed}`].filter(Boolean).join(" | ");
const actualText = (a) => [a.status, a.error, a.failed_check && `rejected by: ${a.failed_check}`].filter(Boolean).join(" | ");

export default function Tester({ announce }) {
  const [cases, setCases] = useState([]);
  const [results, setResults] = useState({});
  const [summary, setSummary] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => { getTesterCases().then((d) => setCases(d.cases), (e) => setError(e.message)); }, []);

  const run = async (which) => {
    setBusy(true); setError(""); announce("Running");
    try {
      const d = await postTesterRun(which);
      setResults((r) => ({ ...r, ...Object.fromEntries(d.results.map((x) => [x.id, x])) }));
      if (which === "all") {
        setSummary(d.summary);
        announce(`Wrong-token tester: ${d.summary.passed} of ${d.summary.total} cases answered correctly, ${d.summary.failed} did not.`);
      } else announce(`${d.results[0].title}: ${d.results[0].pass ? "answered correctly" : "answered incorrectly"}.`);
    } catch (e) { setError(e.status === 429 ? "Another run is in progress. Try again in a moment." : e.message); announce(""); } finally { setBusy(false); }
  };

  return (
    <section aria-labelledby="h-tester">
      <h2 id="h-tester">Wrong-token tester</h2>
      <p className="lede">Fifteen tokens, each wrong in one way (or a control that is right), are sent to a stub MCP-style resource server on loopback. Each row compares what a correct server must answer with what the stub answered, including the <code>WWW-Authenticate</code> challenge and which check did the rejecting. PASS means the stub gave the correct answer for that case.</p>
      <div className="row">
        <button type="button" className="btn primary" onClick={() => run("all")} disabled={busy}>Run all {cases.length || 15} cases</button>
        {summary && <span className="summary" data-testid="tester-summary"><Badge kind={summary.failed ? "deny" : "ok"}>{summary.passed} of {summary.total} correct</Badge></span>}
      </div>
      {error && <p className="alert" role="alert">{error}</p>}
      <div className="table-wrap card" tabIndex={0} role="region" aria-label="Wrong-token cases (scrollable)">
        <table>
          <caption className="sr-only">Wrong-token cases: expected answer, actual answer and result</caption>
          <thead><tr><th scope="col">Case</th><th scope="col">Expected</th><th scope="col">Actual</th><th scope="col">Result</th><th scope="col"><span className="sr-only">Actions</span></th></tr></thead>
          <tbody>
            {cases.map((c) => {
              const r = results[c.id];
              return (
                <React.Fragment key={c.id}>
                  <tr data-case={c.id}>
                    <th scope="row">{c.title}</th>
                    <td className="mono small">{expectText(c.expect)}</td>
                    <td className="mono small">{r ? actualText(r.actual) : "not run"}</td>
                    <td>{r ? <Badge kind={r.pass ? "ok" : "deny"}>{r.pass ? "PASS" : "FAIL"}</Badge> : <Badge kind="mute">not run</Badge>}</td>
                    <td><button type="button" className="btn small-btn" onClick={() => run(c.id)} disabled={busy} aria-label={`Run case: ${c.title}`}>Run</button></td>
                  </tr>
                  <tr className="detail-row">
                    <td colSpan={5}>
                      <details>
                        <summary>Teach me: {c.title}</summary>
                        <p>{c.teaches}</p>
                        {r && (
                          <div className="detail" data-testid={`detail-${c.id}`}>
                            {r.actual.error_description && <p><strong>Server said:</strong> {r.actual.error_description}</p>}
                            <p><strong>WWW-Authenticate:</strong> <code>{r.actual.wwwAuthenticate ?? "(none sent)"}</code></p>
                            <p><strong>Which check rejected it:</strong> {r.actual.failed_check ? <code>{r.actual.failed_check}</code> : r.accepted ? "none, the token was accepted" : "not reported"}</p>
                            <ol className="checks" aria-label="Checks in order">
                              {r.actual.checks.map((k) => <li key={k.id} className={k.pass ? "" : "bad"}>{k.label}: <strong>{k.pass ? "passed" : "REJECTED HERE"}</strong></li>)}
                            </ol>
                            <details><summary>Token sent</summary><pre className="mono raw">{r.token ?? "(no token was sent)"}</pre></details>
                          </div>
                        )}
                      </details>
                    </td>
                  </tr>
                </React.Fragment>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}
