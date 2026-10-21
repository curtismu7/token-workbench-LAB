// Plain text helpers. Server strings are rendered as React text nodes only (never as HTML); these just shape values.
export const show = (v) => (typeof v === "string" ? v : JSON.stringify(v));

export function duration(sec) {
  const s = Math.abs(Math.round(sec));
  const d = Math.floor(s / 86400); const h = Math.floor((s % 86400) / 3600); const m = Math.floor((s % 3600) / 60); const r = s % 60;
  if (d) return `${d}d ${h}h`;
  if (h) return `${h}h ${m}m`;
  if (m) return `${m}m ${r}s`;
  return `${r}s`;
}

export function expiryText(secondsToExpiry) {
  if (secondsToExpiry === null || secondsToExpiry === undefined) return "No exp claim: this token never expires on its own.";
  return secondsToExpiry > 0 ? `Expires in ${duration(secondsToExpiry)}` : `Expired ${duration(secondsToExpiry)} ago`;
}
