// Preflight checks shared by `npm run doctor` and GET /api/health. Synchronous, no network, never prints a secret.
// Each check: { id, level: 'pass' | 'info' | 'fail', detail }.
import { liveFlagProblems, modeFrom, publicOriginFrom } from './config.js';
import { createNetguard } from './netguard.js';
import { REAL_HOW_TO, realConfigFrom } from './real.js';
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

  add('mode', 'pass', 'Mock: stub issuer, stub resource server and stub authorization servers in this process; Real is an owner opt-in (see the real check)');

  // Real (rule 19): why it is or is not available. Names only; never a value (the secret and client id are not printed).
  let hosted = false; try { hosted = modeFrom(env) === 'se-mock'; } catch { /* reported above */ }
  const real = realConfigFrom(hosted ? {} : env);
  if (hosted) add('real', 'pass', 'MODE=se-mock: Real is refused in the hosted build (its settings stop startup)');
  else if (real.available) add('real', 'pass', `Real available: issuer origin ${real.origin}, client id set, client secret set (not shown), ${real.tokenAuth}; Real calls may reach only that origin`);
  else add('real', 'info', `Real unavailable (Mock works): ${real.problems.join('; ')}. ${REAL_HOW_TO}`);

  // The netguard's self-test, in the mode the server starts in (Real when configured, else Mock). It never calls fetch.
  const startMode = real.available ? 'real' : 'mock';
  const st = createNetguard({ mode: () => startMode, allowedOrigin: real.available ? real.origin : null, realFetch: () => { throw new Error('self-test must not fetch'); } }).selfTest();
  add('netguard', st.ok ? 'pass' : 'fail', st.ok ? `self-test ok (${st.checks.length} checks): ${real.available ? 'only the configured issuer origin is reachable' : 'Mock makes no real outbound call'}` : `self-test failed: ${st.checks.filter((c) => !c.ok).map((c) => c.name).join('; ')}`);
  add('outbound', 'pass', real.available
    ? 'Mock: the checker and tester talk to loopback only. Real: https to the configured issuer origin only, through the netguard; the page never sends credentials'
    : 'no outbound calls: the checker and tester talk to loopback only, credentials are never accepted or sent');
  return checks;
}

export const allPassed = (checks) => checks.every((c) => c.level !== 'fail');
