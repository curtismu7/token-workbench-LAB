// Preflight checks shared by `npm run doctor` and GET /api/health. Synchronous, no network, never prints a secret.
// Each check: { id, level: 'pass' | 'info' | 'fail', detail }.
import { STUB_BASE_PORT, STUB_LAST_PORT, assertBindAllowed, bindHost, portInRange, serverPort } from './safety.js';

export function runChecks({ env = process.env } = {}) {
  const checks = [];
  const add = (id, level, detail) => checks.push({ id, level, detail });

  const major = Number(process.versions.node.split('.')[0]);
  add('node', major >= 20 ? 'pass' : 'fail', `v${process.versions.node} (need >= 20)`);

  try { add('bind', 'pass', `${assertBindAllowed(bindHost(env), env)}${env.TW_BIND ? ' (TW_BIND opt-in)' : ' (loopback)'}`); }
  catch (e) { add('bind', 'fail', e.message); }

  const port = serverPort(env);
  add('port-range', portInRange(port) ? 'pass' : 'fail', portInRange(port) ? `server port ${port}, stubs ${STUB_BASE_PORT}-${STUB_LAST_PORT} (all within 5900-5999)` : `server port ${port} is outside 5900-5999`);

  add('mode', 'pass', 'mock only: stub issuer, stub resource server and stub authorization servers in this process; there is no live mode');
  add('outbound', 'pass', 'no outbound settings: the checker and tester talk to loopback only, credentials are never accepted or sent');
  return checks;
}

export const allPassed = (checks) => checks.every((c) => c.level !== 'fail');
