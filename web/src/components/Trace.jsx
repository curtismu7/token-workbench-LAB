import React from "react";
import Badge from "./Badge.jsx";

// The live token flow log of a Real operation: every HTTP exchange with the configured issuer, as sent and as answered.
// Tokens are raw on purpose (education); the client secret was replaced by the server before this list was sent.
// Every value is rendered as text, never as HTML.
const statusKind = (s) => (s === undefined ? "deny" : s >= 200 && s < 300 ? "ok" : s >= 300 && s < 400 ? "hold" : "deny");
const headerText = (h) => Object.entries(h || {}).map(([k, v]) => `${k}: ${v}`).join("\n");

export default function Trace({ entries, title = "REAL trace: HTTP exchanges with the configured issuer" }) {
  if (!Array.isArray(entries) || entries.length === 0) return null;
  return (
    <div className="card" data-testid="trace">
      <div className="row"><h3>{title}</h3><Badge kind="info">REAL</Badge></div>
      <p className="muted small">Request and response as they went over the wire. The client secret is never shown: the server replaced it before sending this log.</p>
      <ol className="trace">
        {entries.map((e, i) => (
          <li key={i} data-step={e.step}>
            <div className="row">
              <strong>{i + 1}. {e.step}</strong>
              <Badge kind={statusKind(e.status)}>{e.status === undefined ? "NO ANSWER" : `HTTP ${e.status}`}</Badge>
              <code className="small">{e.method} {e.url}</code>
            </div>
            {e.error && <p className="alert small">{e.error}</p>}
            {e.note && <p className="note small">{e.note}</p>}
            <details>
              <summary>Request</summary>
              <pre className="mono raw">{`${e.method} ${e.url}\n${headerText(e.request?.headers)}${e.request?.body ? `\n\n${e.request.body}` : ""}`}</pre>
            </details>
            {e.response && (
              <details>
                <summary>Response</summary>
                <pre className="mono raw">{`HTTP ${e.status}\n${headerText(e.response.headers)}\n\n${e.response.body}${e.response.truncated ? "\n[truncated]" : ""}`}</pre>
              </details>
            )}
          </li>
        ))}
      </ol>
    </div>
  );
}
