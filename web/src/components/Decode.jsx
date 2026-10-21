import React, { useEffect, useState } from "react";
import { postDecode, postMint } from "../lib/api.js";
import { expiryText, show } from "../lib/format.js";
import Badge from "./Badge.jsx";

const SAMPLES = [["agent", "Agent token"], ["user", "User token"], ["dpop", "DPoP-bound"], ["mtls", "mTLS-bound"], ["expired", "Expired"]];
const SIG = {
  not_verified: ["hold", "Signature NOT checked"],
  valid_stub_jwks: ["ok", "Signature valid (stub JWKS)"],
  invalid: ["deny", "Signature INVALID"],
};
const LEVEL = { info: null, warn: ["hold", "Warning"], danger: ["deny", "Danger"] };

export default function Decode({ announce }) {
  const [token, setToken] = useState("");
  const [verify, setVerify] = useState(false);
  const [res, setRes] = useState(null);
  const [decodedAt, setDecodedAt] = useState(0);
  const [tick, setTick] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!res?.time?.hasExp) return undefined;
    const t = setInterval(() => setTick((n) => n + 1), 1000);
    return () => clearInterval(t);
  }, [res]);

  const run = async (tok = token, v = verify) => {
    setBusy(true); setError("");
    try {
      const d = await postDecode(tok, v);
      setRes(d); setDecodedAt(Date.now()); setTick(0);
      announce(`Decoded: ${d.claims.length} claims. ${SIG[d.signature.state][1]}.`);
    } catch (e) { setRes(null); setError(e.message); announce(""); } finally { setBusy(false); }
  };
  const mint = async (sample) => {
    setBusy(true); setError("");
    try { const m = await postMint(sample); setToken(m.token); await run(m.token, verify); } catch (e) { setError(e.message); setBusy(false); }
  };

  const elapsed = res ? Math.floor((Date.now() - decodedAt) / 1000) : 0; void tick;
  const left = res?.time?.secondsToExpiry == null ? null : res.time.secondsToExpiry - elapsed;
  const cnf = res?.claims.filter((c) => c.name === "cnf" || c.name.startsWith("cnf."));

  return (
    <section aria-labelledby="h-decode">
      <h2 id="h-decode">Decode and trace a token</h2>
      <p className="lede">Paste a JWT or mint a sample signed by the stub issuer. The token is decoded in the server without a network call and every claim is explained. Raw tokens are shown on purpose, because this is a debugging tool; they are never logged or sent anywhere.</p>
      <div className="card">
        <label htmlFor="tok" className="lbl">Token (JWT)</label>
        <textarea id="tok" className="tok mono" rows={4} value={token} spellCheck={false} autoComplete="off" onChange={(e) => setToken(e.target.value)} placeholder="eyJ..." />
        <div className="row">
          <button type="button" className="btn primary" onClick={() => run()} disabled={busy || !token.trim()}>Decode</button>
          <label className="check"><input type="checkbox" checked={verify} onChange={(e) => setVerify(e.target.checked)} /> Verify the signature against the stub JWKS</label>
        </div>
        <div className="row" role="group" aria-label="Mint a sample token">
          <span className="muted small">Mint a sample:</span>
          {SAMPLES.map(([id, label]) => <button key={id} type="button" className="btn" onClick={() => mint(id)} disabled={busy}>{label}</button>)}
        </div>
      </div>
      {error && <p className="alert" role="alert">{error}</p>}
      {res && (
        <>
          <div className="card result" data-testid="decode-result">
            <div className="row">
              <Badge kind={SIG[res.signature.state][0]}>{SIG[res.signature.state][1]}</Badge>
              {res.time.hasExp && (
                <span role="timer" className={`timer ${left <= 0 ? "timer--out" : ""}`} data-testid="countdown">{expiryText(left)}</span>
              )}
              {res.time.notYetValid && <Badge kind="hold">Not valid yet (nbf)</Badge>}
            </div>
            <p className="note">{res.signature.note}</p>
          </div>
          {cnf?.length > 0 && (
            <div className="card callout" data-testid="cnf-note">
              <h3>Sender binding (cnf): decoded, not enforced</h3>
              <p>{cnf.map((c) => c.meaning).join(" ")}</p>
              <p><strong>This workbench only reads and explains cnf.</strong> It does not check a DPoP proof or a client certificate, and neither does the stub resource server. A bound token is only protected where the server enforces the binding.</p>
            </div>
          )}
          <div className="card">
            <h3>Claims</h3>
            <div className="table-wrap">
              <table>
                <caption className="sr-only">Header and payload claims with a plain-English explanation</caption>
                <thead><tr><th scope="col">Claim</th><th scope="col">Value</th><th scope="col">In plain English</th></tr></thead>
                <tbody>
                  {res.claims.map((c) => (
                    <tr key={c.name}>
                      <th scope="row" className="mono">{c.name}</th>
                      <td><code>{show(c.value)}</code></td>
                      <td>{LEVEL[c.level] && <><Badge kind={LEVEL[c.level][0]}>{LEVEL[c.level][1]}</Badge>{" "}</>}{c.meaning}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <details>
              <summary>Raw header and payload</summary>
              <pre className="mono raw">{JSON.stringify({ header: res.header, payload: res.payload }, null, 2)}</pre>
            </details>
          </div>
        </>
      )}
    </section>
  );
}
