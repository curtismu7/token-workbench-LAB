// Workspace registry (rule 13), used in MODE=se-mock only. One complete runtime (stub issuer keys, five stub
// authorization servers, stub resource server, run queue, code and request stores) per workspace id, so one visitor's
// tokens, runs and results can never be read or changed by another. The id arrives in the X-Workspace-Id header (default
// 'default'). It is a label, not a credential, and everything behind it is synthetic.
// Capped, with idle eviction: past `max` the least recently used idle non-default workspace is dropped (and its
// listeners closed); a workspace idle for `ttlMs` is dropped on the next sweep. A busy workspace (a run in progress) is
// never evicted. If the cap is reached and nothing can be evicted, the request is refused (503), never queued.
export const DEFAULT_WORKSPACE = 'default';
export const MAX_WORKSPACES = 20;
export const WORKSPACE_TTL_MS = 30 * 60 * 1000;
export const WORKSPACE_RE = /^[a-z0-9][a-z0-9-]{0,31}$/;

export function createWorkspaces({ defaultRuntime, create, max = MAX_WORKSPACES, ttlMs = WORKSPACE_TTL_MS, now = () => Date.now(), sweepMs = 60_000 }) {
  // Map keeps insertion order; a touched entry is re-inserted, so the first non-default key is the least recently used.
  const map = new Map([[DEFAULT_WORKSPACE, { runtime: Promise.resolve(defaultRuntime), last: now(), ref: defaultRuntime }]]);
  const drop = (id) => { const e = map.get(id); map.delete(id); e.runtime.then((rt) => rt.close()).catch(() => {}); };
  // An entry whose runtime is still being created (ref null) counts as busy, so it cannot be evicted mid-creation.
  const idle = (e) => !!e.ref && !e.ref.busy?.();

  function sweep() {
    const t = now();
    for (const [id, e] of [...map]) if (id !== DEFAULT_WORKSPACE && t - e.last > ttlMs && idle(e)) drop(id);
  }
  const timer = setInterval(sweep, sweepMs);
  timer.unref();

  return {
    // Resolves to the workspace's runtime, creating it on first use. Rejects with code 'workspace_cap' when full.
    get(id = DEFAULT_WORKSPACE) {
      sweep();
      const hit = map.get(id);
      if (hit) {
        hit.last = now();
        if (id !== DEFAULT_WORKSPACE) { map.delete(id); map.set(id, hit); }
        return hit.runtime;
      }
      while (map.size >= max) {
        const victim = [...map].find(([k, e]) => k !== DEFAULT_WORKSPACE && idle(e));
        if (!victim) return Promise.reject(Object.assign(new Error('too many active workspaces'), { code: 'workspace_cap' }));
        drop(victim[0]);
      }
      const entry = { last: now(), ref: null, runtime: null };
      entry.runtime = Promise.resolve().then(create).then((rt) => { entry.ref = rt; return rt; });
      entry.runtime.catch(() => { if (map.get(id) === entry) map.delete(id); });
      map.set(id, entry);
      return entry.runtime;
    },
    sweep,
    get size() { return map.size; },
    ids: () => [...map.keys()],
    async closeAll() {
      clearInterval(timer);
      const others = [...map].filter(([k]) => k !== DEFAULT_WORKSPACE);
      for (const [k] of others) map.delete(k);
      await Promise.all(others.map(([, e]) => e.runtime.then((rt) => rt.close()).catch(() => {})));
    },
  };
}
