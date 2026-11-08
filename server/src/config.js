// Deployment mode (rule 18). One image, one switch: MODE=local (default, the standalone) or MODE=se-mock (the hosted,
// simulated build on the SE k8s cluster). Anything else is an error, never a silent fallback.
// In se-mock every live-ish feature is compiled out or refused: the checker accepts the per-workspace loopback stubs
// only (no user-typed target), and a live flag in the environment stops the server from starting.
export const MODES = ['local', 'se-mock'];
// Names this app has never honoured. Setting one in se-mock is refused loudly so that a manifest edit cannot imply a
// live capability that does not exist.
export const REFUSED_LIVE_ENV = ['TW_LIVE', 'TW_ALLOW_REMOTE', 'TW_ALLOW_TARGETS', 'TW_CHECKER_TARGETS', 'LIVE'];

export function modeFrom(env = process.env) {
  const m = env.MODE === undefined || env.MODE === '' ? 'local' : env.MODE;
  if (!MODES.includes(m)) throw new Error(`MODE=${String(m).replace(/[^\x20-\x7e]/g, '?').slice(0, 20)} is not available: use local or se-mock (there is no live mode)`);
  return m;
}

// Problems that make se-mock refuse to start (empty list in local mode, where these settings are not consulted).
export function liveFlagProblems(env = process.env) {
  if (modeFrom(env) !== 'se-mock') return [];
  return REFUSED_LIVE_ENV.filter((k) => env[k] !== undefined && env[k] !== '').map((k) => `${k} is set: live features are refused in MODE=se-mock`);
}

// The browser-visible origin of the hosted build (https://<SE host>, rendered into the manifest by k8s/deploy.sh). The
// ingress rewrites the Host header to loopback, so a same-origin POST arrives with Origin = this value. Only that exact
// https origin is accepted in addition to loopback origins; null means none configured.
export function publicOriginFrom(env = process.env) {
  const v = env.TW_PUBLIC_ORIGIN;
  if (v === undefined || v === '') return null;
  let u = null;
  try { u = new URL(v); } catch { /* checked below */ }
  if (!u || u.protocol !== 'https:' || u.origin !== v || u.username || u.password) throw new Error('TW_PUBLIC_ORIGIN must be a plain https origin such as https://host.example');
  return u.origin;
}

// Extra Host names this app answers to (family standard): LAB_ALLOWED_HOSTS, comma separated host names that point at this Mac,
// such as the lab-proxy's token-workbench.local.ping-devops.com. Loopback always works; unset = loopback only.
const HOSTNAME = /^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/i;
export function allowedHostsFrom(env = process.env) {
  const names = String(env.LAB_ALLOWED_HOSTS || '').split(',').map((h) => h.trim().toLowerCase()).filter(Boolean);
  for (const h of names) if (!HOSTNAME.test(h)) throw new Error(`LAB_ALLOWED_HOSTS: not a host name: ${h}`);
  return new Set(names);
}

export const bannerText = (mode) => (mode === 'se-mock'
  ? 'HOSTED SIMULATION: this is a shared hosted demo. Every stub server, key and token here is simulated and lives in memory in the server, private to your browser tab. Nothing real is contacted and you cannot point it at anything.'
  : null);
