// Builds what the API serves from: the stub issuer keys, five stub authorization servers and the stub resource server,
// all in this process on loopback. Mock only; there is no live mode.
import { createKeyring, identifiers } from './keys.js';
import { startAuthServer, PROFILE_ORDER } from './stubs/authserver.js';
import { startResourceServer } from './stubs/resource.js';
import { STUB_BASE_PORT } from './safety.js';

export async function createRuntime({ stubBase = STUB_BASE_PORT, now = () => Date.now() / 1000 } = {}) {
  const rsPort = stubBase + PROFILE_ORDER.length;
  const ids = identifiers(rsPort);
  const keyring = createKeyring({ issuer: ids.issuer });
  const started = [];
  try {
    const authServers = {};
    for (const [i, profile] of PROFILE_ORDER.entries()) { const s = await startAuthServer({ port: stubBase + i, profile }); started.push(s); authServers[profile] = s; }
    const rs = await startResourceServer({ port: rsPort, keyring, audience: ids.resource, now });
    started.push(rs);

    // Runs of the checker and the tester go through one queue: one runs, at most one waits, a third is refused (429).
    let chain = Promise.resolve();
    let pending = 0;
    const enqueue = (fn) => {
      if (pending >= 2) return Promise.reject(Object.assign(new Error('a run is in progress and another is already queued'), { code: 'run_queue_full' }));
      pending += 1;
      const run = chain.then(fn);
      chain = run.catch(() => {}).then(() => { pending -= 1; });
      return run;
    };

    return {
      mode: 'mock', keyring, ids, authServers, rs, now, enqueue,
      testerCtx: { keyring, ids, now, rsUrl: rs.url },
      ports: [...started.map((s) => s.port)],
      close: async () => { await Promise.all(started.map((s) => s.close())); },
    };
  } catch (e) { await Promise.all(started.map((s) => s.close())); throw e; }
}
