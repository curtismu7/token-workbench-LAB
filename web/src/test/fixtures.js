// Fixtures shaped like the server's real answers. No JWT-shaped literals: tokens are assembled at runtime.
const b64u = (o) => btoa(JSON.stringify(o)).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
export const fakeToken = (payload = { sub: "u" }) => [b64u({ alg: "ES256" }), b64u(payload), "sig"].join(".");

export const HEALTH = { schema: "demo-health/1", state: "ready", runtime: "offline" };
export const EVIL = "<img src=x onerror=alert(1)>";

export const decoded = (over = {}) => ({
  header: { alg: "ES256", kid: "k1" },
  payload: { sub: EVIL, exp: 4102444800 },
  claims: [
    { name: "alg", value: "ES256", meaning: "The signature algorithm.", level: "info" },
    { name: "sub", value: EVIL, meaning: "The subject: who the token is about.", level: "info" },
    { name: "cnf.jkt", value: "abc", meaning: "Sender-constrained with DPoP (RFC 9449).", level: "info" },
    { name: "cnf", value: null, meaning: "No cnf claim: this is a bearer token.", level: "warn" },
  ],
  time: { hasExp: true, expired: false, secondsToExpiry: 300, notYetValid: false },
  signature: { state: "not_verified", note: "The signature was not checked. Anyone can write any claims." },
  signaturePresent: true,
  ...over,
});

export const CASES = [
  { id: "good", title: "Correct token (control)", teaches: "All checks pass.", expect: { status: 200 } },
  { id: "wrong-scope", title: "Wrong scope", teaches: "Genuine token, missing permission.", expect: { status: 403, error: "insufficient_scope", failed: "scope" } },
];
export const caseResult = (id, over = {}) => ({
  id, title: CASES.find((c) => c.id === id).title, teaches: "x", expect: CASES.find((c) => c.id === id).expect, pass: true, accepted: id === "good", token: fakeToken(),
  actual: { status: id === "good" ? 200 : 403, error: id === "good" ? null : "insufficient_scope", error_description: "needs mcp:tools", failed_check: id === "good" ? null : "scope", wwwAuthenticate: id === "good" ? null : 'Bearer error="insufficient_scope"', wwwError: null,
    checks: [{ id: "signature", label: "signature verifies", pass: true }, { id: "scope", label: "has the required scope", pass: id === "good" }] },
  ...over,
});

export const META = { profiles: [{ id: "good", title: "Good profile", blurb: "Everything on.", url: "http://127.0.0.1:5911" }, { id: "no-pkce", title: "No PKCE", blurb: "PKCE off.", url: "http://127.0.0.1:5914" }] };
export const CHECK = {
  target: "http://127.0.0.1:5914", metadata: { found: true },
  packs: {
    bcp: { title: "RFC 9700 BCP", unverified: false, note: "Rules are this demo's paraphrase of RFC 9700. Only RFC numbers are cited, not section numbers.", rules: [{ id: "pkce-required", title: "PKCE is required", rfc: "RFC 7636", why: "Because.", status: "fail", evidence: "issued a code with no challenge" }, { id: "metadata", title: "Metadata", rfc: "RFC 8414", why: "w", status: "pass", evidence: "found" }] },
    fapi: { title: "FAPI 2.0 (simplified)", unverified: true, note: "UNVERIFIED: this FAPI 2.0 pack is a simplified reading.", rules: [{ id: "fapi-par-published", title: "PAR is published", rfc: "RFC 9126", why: "w", status: "fail", evidence: "no endpoint" }] },
  },
};

const mech = (id, name) => ({ id, name, rfc: "RFC", adds: `${name} adds a thing.`, attack: { id: "a", title: `${name} attack`, description: "d" }, limits: `${name} limits.` });
export const COMPARE = { simulated: true, rows: ["pkce", "dpop"].map((id) => ({ ...mech(id, id.toUpperCase()), without: { outcome: "attack_succeeds", pass: false }, with: { outcome: "attack_blocked", pass: true } })) };
export const flowRun = (id, prot) => ({
  mechanism: mech(id, id.toUpperCase()), protected: prot, simulated: true,
  steps: [{ n: 1, from: "client", to: "as", label: "get a token", evil: false }, { n: 2, from: "attacker", to: "rs", label: "replay it", evil: true }],
  attack: { id: "a", title: "t", description: "d", outcome: prot ? "attack_blocked" : "attack_succeeds", reason: prot ? "refused" : "accepted" },
  pass: prot,
});

// A fetch stub keyed by "METHOD /path". Records every call.
export function stubFetch(routes) {
  const calls = [];
  const fn = vi.fn(async (path, init = {}) => {
    const method = init.method || "GET";
    calls.push({ path, method, init });
    const r = routes[`${method} ${path}`];
    if (!r) return { ok: false, status: 404, json: async () => ({ error: "not_found" }) };
    const out = typeof r === "function" ? r(init.body ? JSON.parse(init.body) : undefined) : r;
    return out.__status ? { ok: false, status: out.__status, json: async () => out.body } : { ok: true, status: 200, json: async () => out };
  });
  vi.stubGlobal("fetch", fn);
  return calls;
}
