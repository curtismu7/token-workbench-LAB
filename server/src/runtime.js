// Builds what the API serves from: the stub issuer keys, five stub authorization servers and the stub resource server,
// all in this process on loopback. This is Mock; Real (real.js) never uses these stubs.
import { createKeyring, identifiers } from './keys.js';
import { startAuthServer, PROFILE_ORDER } from './stubs/authserver.js';
import { startResourceServer } from './stubs/resource.js';
import net from 'node:net';
import { STUB_BASE_PORT } from './safety.js';

// Free loopback ports for the extra (per-workspace) runtimes of MODE=se-mock. The default runtime keeps the fixed
// 5911-5916; these stubs live on the pod's own loopback and are never published.
async function freePorts(n) {
  const servers = [];
  try {
    for (let i = 0; i < n; i += 1) {
      const s = net.createServer();
      await new Promise((resolve, reject) => { s.once('error', reject); s.listen(0, '127.0.0.1', resolve); });
      servers.push(s);
    }
    return servers.map((s) => s.address().port);
  } finally { await Promise.all(servers.map((s) => new Promise((r) => { s.close(r); }))); }
}

// ports: [five authorization-server ports, resource-server port]. Default: stubBase .. stubBase+5. ephemeral: pick free ports.
export async function createRuntime({ stubBase = STUB_BASE_PORT, now = () => Date.now() / 1000, ephemeral = false } = {}) {
  for (let attempt = 0; ; attempt += 1) {
    try { return await build({ ports: ephemeral ? await freePorts(PROFILE_ORDER.length + 1) : null, stubBase, now }); } catch (e) { if (!ephemeral || e.code !== 'EADDRINUSE' || attempt >= 4) throw e; }
  }
}

async function build({ ports, stubBase, now }) {
  const portAt = (i) => (ports ? ports[i] : stubBase + i);
  const rsPort = portAt(PROFILE_ORDER.length);
  const ids = identifiers(rsPort);
  const keyring = createKeyring({ issuer: ids.issuer });
  const started = [];
  try {
    const authServers = {};
    for (const [i, profile] of PROFILE_ORDER.entries()) { const s = await startAuthServer({ port: portAt(i), profile }); started.push(s); authServers[profile] = s; }
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
      mode: 'mock', keyring, ids, authServers, rs, now, enqueue, busy: () => pending > 0,
      testerCtx: { keyring, ids, now, rsUrl: rs.url },
      ports: [...started.map((s) => s.port)],
      close: async () => { await Promise.all(started.map((s) => s.close())); },
    };
  } catch (e) { await Promise.all(started.map((s) => s.close())); throw e; }
}
