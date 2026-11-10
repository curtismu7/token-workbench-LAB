import React from "react";

// Rule 19: what Real needs, shown honestly. Names only: the server never sends a setting's value.
export default function RealStatus({ info }) {
  if (!info || info.hosted || !info.real) return null;
  const r = info.real;
  if (info.realAvailable) return null; // the Real banner already names the issuer
  return (
    <details className="card" data-testid="real-status">
      <summary>Real not configured: Mock only for now. How to turn Real on</summary>
      <p className="small">{r.howTo}</p>
      {r.problems?.length > 0 && (
        <ul className="small" data-testid="real-problems">{r.problems.map((p) => <li key={p}>{p}</li>)}</ul>
      )}
      <div className="table-wrap" tabIndex={0} role="region" aria-label="Real settings (scrollable)">
        <table>
          <caption className="sr-only">The settings Real needs, in the lab's .env file</caption>
          <thead><tr><th scope="col">Setting</th><th scope="col">Needed</th><th scope="col">What it is</th><th scope="col">State</th></tr></thead>
          <tbody>
            {r.settings.map((s) => (
              <tr key={s.name}>
                <th scope="row" className="mono">{s.name}</th>
                <td>{s.required ? "required" : "optional"}</td>
                <td className="small">{s.about}</td>
                <td>{r.missing.includes(s.name) ? <strong>missing or invalid</strong> : s.required ? "ok" : ""}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="muted small">Real is owner-run: it sends a client_credentials request, a JWKS fetch, introspection and a metadata read to that one issuer, and nothing else.</p>
    </details>
  );
}
