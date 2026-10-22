// Preflight checks shared by `npm run doctor` and GET /api/health. Synchronous, no network, never prints a secret.
// Each check: { id, level: 'pass' | 'info' | 'fail', detail }.
import { liveFlagProblems, modeFrom, publicOriginFrom } from './config.js';
import { STUB_BASE_PORT, STUB_LAST_PORT, assertBindAllowed, bindHost, portInRange, serverPort } from './safety.js';

export function runChecks({ env = process.env } = {}) {
  const checks = [];
  const add = (id, level, detail) => checks.push({ id, level, detail });

  const major = Number(process.versions.node.split('.')[0]);
  const minor = Number(process.versions.node.split('.')[1]);
  const nodeOk = major > 20 || (major === 20 && minor >= 12); // process.loadEnvFile (.env) arrived in 20.12
  add('node', nodeOk ? 'pass' : 'fail', `v${process.versions.node} (need >= 20.12)`);

  try { add('bind', 'pass', `${assertBindAllowed(bindHost(env), env)}${env.TW_BIND ? ' (TW_BIND opt-in)' : ' (loopback)'}`); }
  catch (e) { add('bind', 'fail', e.message); }

  const port = serverPort(env);
  add('port-range', portInRange(port) ? 'pass' : 'fail', portInRange(port) ? `server port ${port}, stubs ${STUB_BASE_PORT}-${STUB_LAST_PORT} (all within 5900-5999)` : `server port ${port} is outside 5900-5999`);

  try {
    const mode = modeFrom(env);
    const bad = liveFlagProblems(env);
    if (bad.length) add('deploy-mode', 'fail', bad.join('; '));
    else if (mode === 'se-mock') {
      const origin = publicOriginFrom(env);
      add('deploy-mode', origin ? 'pass' : 'info', origin ? `MODE=se-mock (hosted and simulated); public origin ${origin}` : 'MODE=se-mock without TW_PUBLIC_ORIGIN: only loopback origins are accepted for POSTs (the k8s manifest sets it)');
    } else add('deploy-mode', 'pass', 'MODE=local (the standalone)');
  } catch (e) { add('deploy-mode', 'fail', e.message); }

  add('mode', 'pass', 'mock only: stub issuer, stub resource server and stub authorization servers in this process; there is no live mode');
  add('outbound', 'pass', 'no outbound settings: the checker and tester talk to loopback only, credentials are never accepted or sent');
  return checks;
}

export const allPassed = (checks) => checks.every((c) => c.level !== 'fail');
