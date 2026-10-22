import { fileURLToPath } from 'node:url';
import { startHttpServer } from './app.js';
import { allPassed, runChecks } from './doctor.js';

// Local runs read the repo-root .env (real env vars win). The hosted build (MODE=se-mock) never reads a file.
if (process.env.MODE !== 'se-mock') try { process.loadEnvFile(fileURLToPath(new URL('../../.env', import.meta.url))); } catch { /* no .env */ }

const checks = runChecks();
if (!allPassed(checks)) {
  for (const c of checks.filter((x) => x.level === 'fail')) console.error(`[token-workbench] refusing to start: ${c.id}: ${c.detail}`);
  process.exit(1);
}
const { url, runtime } = await startHttpServer();
console.log(`[token-workbench] MOCK mode (${process.env.MODE === 'se-mock' ? 'hosted, se-mock' : 'local'}) at ${url} (loopback unless TW_BIND is set)`);
console.log(`[token-workbench] API: GET ${url}api/health | GET ${url}api/meta | POST ${url}api/decode | POST ${url}api/tester/run | POST ${url}api/checker/run | GET ${url}api/flows/compare`);
console.log(`[token-workbench] stubs on 127.0.0.1:${runtime.ports.join(', ')}`);
