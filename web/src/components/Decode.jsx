import React, { useEffect, useState } from "react";
import { postDecode, postIntrospect, postMint, postSignIn, postSigninRefresh, postSigninSignout, getSigninSession } from "../lib/api.js";
import { expiryText, show } from "../lib/format.js";
import Badge from "./Badge.jsx";
import Trace from "./Trace.jsx";

const SAMPLES = [["agent", "Agent token"], ["user", "User token"], ["dpop", "DPoP-bound"], ["mtls", "mTLS-bound"], ["expired", "Expired"]];
const SIG = {
  not_verified: ["hold", "Signature NOT checked"],
  valid_stub_jwks: ["ok", "Signature valid (stub JWKS)"],
  valid_real_jwks: ["ok", "Signature valid (issuer's real JWKS)"],
  invalid: ["deny", "Signature INVALID"],
};
const LEVEL = { info: null, warn: ["hold", "Warning"], danger: ["deny", "Danger"] };

// source: "mock" or "real" (the server's mode). The component is remounted on a switch, so state never crosses modes.
// signinProviders: the configured sign-in IdPs from /api/info (PingOne, PingFederate or both).
export default function Decode({ announce, source = "mock", signinProviders = [] }) {
  const real = source === "real";
  const [token, setToken] = useState("");
  const [label, setLabel] = useState(null); // MOCK or REAL for a minted token; null for a pasted one
  const [trace, setTrace] = useState(null);
  const [intro, setIntro] = useState(null);
  const [verify, setVerify] = useState(false);
  const [res, setRes] = useState(null);
  const [decodedAt, setDecodedAt] = useState(0);
  const [tick, setTick] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  // Real sign-in: the three tokens from the pi.flow sign-in, the kind being viewed, and the dialog's fields.
  const [userTokens, setUserTokens] = useState(null); // [{kind, label, token, header, claims}] or null
  const [viewKind, setViewKind] = useState("access");
  const [pw, setPw] = useState("");
  const [showPw, setShowPw] = useState(false);
  const [signedIn, setSignedIn] = useState(false);
  const [provider, setProvider] = useState("pingone"); // which IdP the sign-in goes to
  const providerList = signinProviders.length ? signinProviders : [];

  useEffect(() => {
    if (!real) return undefined;
    // While signed in the session's trace (the sign-in / refresh exchanges) stays visible across reloads.
    getSigninSession().then((s) => { setSignedIn(!!s?.signedIn); if (s?.provider) setProvider(s.provider); if (s?.signedIn && s.trace) setTrace(s.trace); }, () => {});
    return undefined;
  }, [real]);

  useEffect(() => {
    if (!res?.time?.hasExp) return undefined;
    const t = setInterval(() => setTick((n) => n + 1), 1000);
    return () => clearInterval(t);
  }, [res]);

  const run = async (tok = token, v = verify) => {
    setBusy(true); setError(""); setIntro(null);
    try {
      const d = await postDecode(tok, v);
      setRes(d); setDecodedAt(Date.now()); setTick(0); setTrace(d.trace || trace);
      announce(`Decoded: ${d.claims.length} claims. ${SIG[d.signature.state][1]}.`);
    } catch (e) { setRes(null); setError(e.message); setTrace(e.data?.trace || null); announce(""); } finally { setBusy(false); }
  };
  const mint = async (sample) => {
    setBusy(true); setError(""); setIntro(null);
    try { const m = await postMint(sample); setToken(m.token); setLabel(m.label || null); await run(m.token, verify); if (m.trace) setTrace((t) => [...m.trace, ...(t || [])]); }
    catch (e) { setError(e.message); setTrace(e.data?.trace || null); setBusy(false); }
  };
  const introspect = async () => {
    setBusy(true); setError("");
    try { const d = await postIntrospect(token.trim()); setIntro(d); setTrace(d.trace || trace); announce(`Introspection: ${d.active ? "active" : "not active"}.`); }
    catch (e) { setIntro(null); setError(e.message); setTrace(e.data?.trace || null); announce(""); } finally { setBusy(false); }
  };

  // --- Real sign-in (pi.flow): password typed once, sent once, never stored ---
  const pickUserToken = (kind, list = userTokens) => {
    const t = (list || []).find((x) => x.kind === kind);
    if (!t?.token) { setToken(""); setRes(null); setLabel(null); setTrace(null); return; }
    setToken(t.token); setLabel("REAL"); setViewKind(kind);
    setRes({ header: t.header, payload: t.claims, claims: [], signature: { state: "not_verified", note: kind === "refresh" ? "A refresh token is data, not a JWT: there is no signature to check. Introspection does not apply to it either." : "Decode is offline. Tick the box to verify the signature against the issuer's real JWKS." }, time: { hasExp: false } });
    setTrace(null); setIntro(null); setDecodedAt(Date.now());
    if (kind !== "refresh") run(t.token, verify);
  };
  const doSignIn = async () => {
    setBusy(true); setError(""); setIntro(null);
    try {
      const r = await postSignIn(pw, provider);
      setPw(""); setShowPw(false); setSignedIn(true); setUserTokens(r.tokens); setTrace(r.trace || null);
      announce(`Signed in to ${provider === "pingfederate" ? "PingFederate" : "PingOne"}. Access, ID and refresh tokens are ready.`);
      pickUserToken(viewKind, r.tokens);
    } catch (e) { setError(e.message); setTrace(e.data?.trace || null); announce(""); } finally { setBusy(false); }
  };
  const doRefresh = async () => {
    setBusy(true); setError("");
    try {
      const r = await postSigninRefresh();
      setUserTokens(r.tokens); setTrace(r.trace || null);
      announce("Refreshed: the issuer issued a new access token.");
      pickUserToken(viewKind, r.tokens);
    } catch (e) {
      if (e.status === 401 && /no sign-in session/.test(e.message)) { setSignedIn(false); setUserTokens(null); setTrace(null); }
      setError(e.message); setTrace(e.data?.trace || null); announce("");
    } finally { setBusy(false); }
  };
  const doSignOut = async () => {
    setBusy(true); setError("");
    try { await postSigninSignout(); } catch { /* the session is gone either way */ }
    setSignedIn(false); setUserTokens(null); setToken(""); setRes(null); setLabel(null); setTrace(null); setIntro(null);
    announce("Signed out: the sign-in session is dropped.");
    setBusy(false);
  };

  const elapsed = res ? Math.floor((Date.now() - decodedAt) / 1000) : 0; void tick;
  const left = res?.time?.secondsToExpiry == null ? null : res.time.secondsToExpiry - elapsed;
  const cnf = res?.claims.filter((c) => c.name === "cnf" || c.name.startsWith("cnf."));

  return (
    <section aria-labelledby="h-decode">
      <h2 id="h-decode">Decode and trace a token</h2>
      {real
        ? <p className="lede">REAL: get an access token from the configured issuer with the client_credentials grant, verify a token against the issuer's real JWKS, or introspect it at the issuer. Decoding itself still makes no network call. Every request to the issuer is listed in the trace below. Raw tokens are shown on purpose, because this is a debugging tool; they are never logged.</p>
        : <p className="lede">Paste a JWT or mint a sample signed by the stub issuer. The token is decoded in the server without a network call and every claim is explained. Raw tokens are shown on purpose, because this is a debugging tool; they are never logged or sent anywhere.</p>}
      <div className="card">
        <div className="row">
          <label htmlFor="tok" className="lbl">Token (JWT)</label>
          {label && <Badge kind={label === "REAL" ? "hold" : "info"} title={label === "REAL" ? "Issued by the configured real issuer" : "Signed by the stub issuer in this process"}><span data-testid="token-label">{label}</span></Badge>}
        </div>
        <textarea id="tok" className="tok mono" rows={Math.max(4, token.split("\n").length + Math.ceil(token.length / 120))} value={token} spellCheck={false} autoComplete="off" onChange={(e) => { setToken(e.target.value); setLabel(null); }} placeholder="eyJ..." />
        <div className="row">
          <button type="button" className="btn primary" onClick={() => run()} disabled={busy || !token.trim()}>Decode</button>
          <label className="check"><input type="checkbox" checked={verify} onChange={(e) => setVerify(e.target.checked)} /> {real ? "Verify the signature against the issuer's real JWKS" : "Verify the signature against the stub JWKS"}</label>
          <button type="button" className="btn" onClick={introspect} disabled={busy || !token.trim()}>{real ? "Introspect at the issuer" : "Introspect (stub issuer)"}</button>
        </div>
        {real ? (
          <>
            <div className="row" role="group" aria-label="Get a real token">
              <span className="muted small">Get a token:</span>
              <button type="button" className="btn" onClick={() => mint("client_credentials")} disabled={busy}>REAL client_credentials token</button>
            </div>
            <div className="row" role="group" aria-label="Sign in">
              <span className="muted small">User sign-in:</span>
              <span className="muted small" title="Which server the sign-in goes to. Only the ones configured in the lab's .env are offered.">Sign in to:</span>
              <select aria-label="Sign-in provider" value={provider} onChange={(e) => setProvider(e.target.value)} disabled={busy || signedIn || providerList.length < 2}>
                {(providerList.length ? providerList : [{ id: "pingone", label: "PingOne" }]).map((p) => <option key={p.id} value={p.id}>{p.label}</option>)}
              </select>
              {signedIn ? (
                <>
                  <button type="button" className="btn" onClick={doRefresh} disabled={busy} title="Exchanges the refresh token for a new access (and ID) token at the same server">Refresh tokens</button>
                  <button type="button" className="btn" onClick={doSignOut} disabled={busy} title="Drops this lab's copy of the sign-in session. The issuer's tokens stay valid until they expire.">Sign out</button>
                </>
              ) : (
                <>
                  <input type={showPw ? "text" : "password"} className="pw mono" value={pw} autoComplete="off" spellCheck={false} placeholder="password for the sign-in" aria-label="Password for the sign-in" onChange={(e) => setPw(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter" && pw && !busy) doSignIn(); }} />
                  <button type="button" className="btn" onClick={() => setShowPw((v) => !v)} aria-pressed={showPw} title="Show or hide what you typed">{showPw ? "Hide" : "Show"}</button>
                  <button type="button" className="btn primary" onClick={doSignIn} disabled={busy || !pw} title={`Runs an authorization-code + PKCE sign-in with response_mode=pi.flow at ${provider === "pingfederate" ? "the configured PingFederate" : "the configured PingOne environment"}: the login stays in this page, no redirect. The password is sent once to the server you picked and never stored, logged or shown.`}>Sign in</button>
                </>
              )}
            </div>
            {!signedIn && pw && (
              <p className="muted small">Sign in runs authorization code + PKCE with <code>response_mode=pi.flow</code> at {provider === "pingfederate" ? "PingFederate" : "PingOne"}: the login form stays in this page (no browser redirect). The password is sent once, over the trace below, never stored or shown. On success the issuer returns three tokens — access, ID and refresh — each shown raw under “View”.</p>
            )}
            {userTokens && (
              <div className="row" role="group" aria-label="Which token to view">
                <span className="muted small">View:</span>
                {userTokens.map((t) => (
                  <button key={t.kind} type="button" className={`btn ${viewKind === t.kind ? "primary" : ""}`} data-testid={`token-kind-${t.kind}`} onClick={() => pickUserToken(t.kind)} disabled={!t.token} title={t.token ? t.label : "the issuer issued none"}>
                    {t.label}
                  </button>
                ))}
              </div>
            )}
          </>
        ) : (
          <div className="row" role="group" aria-label="Mint a sample token">
            <span className="muted small">Mint a sample:</span>
            {SAMPLES.map(([id, name]) => <button key={id} type="button" className="btn" onClick={() => mint(id)} disabled={busy}>{name}</button>)}
          </div>
        )}
      </div>
      {error && <p className="alert" role="alert">{error}</p>}
      {intro && (
        <div className="card result" data-testid="introspect-result">
          <div className="row">
            <Badge kind={intro.active ? "ok" : "deny"}>{intro.active ? "ACTIVE" : "NOT ACTIVE"}</Badge>
            <Badge kind={intro.source === "real" ? "hold" : "info"}>{intro.source === "real" ? "REAL" : "MOCK"}</Badge>
          </div>
          <p className="note">{intro.source === "real" ? "The configured issuer answered (RFC 7662); its raw answer is in the trace." : intro.note}</p>
          {intro.response && <pre className="mono raw">{JSON.stringify(intro.response, null, 2)}</pre>}
        </div>
      )}
      <Trace entries={trace} />
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
            <div className="table-wrap" tabIndex={0} role="region" aria-label="Claims table (scrollable)">
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
