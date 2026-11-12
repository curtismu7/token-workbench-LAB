// Thin fetch wrapper. JSON in, JSON out. No credential headers, no cookies: the server refuses them. The token under
// test is DATA in a JSON body, never an Authorization header.
// One workspace per browser tab (sessionStorage), so a hosted visitor's keys, runs and results are private to the tab.
// The id is a label, not a credential. The local build ignores the header.
let memoryId = null;
export function workspaceId() {
  try {
    let id = sessionStorage.getItem("tw-workspace");
    if (!id) { id = newId(); sessionStorage.setItem("tw-workspace", id); }
    return id;
  } catch { memoryId ||= newId(); return memoryId; }
}
function newId() {
  const bytes = new Uint8Array(8);
  try { crypto.getRandomValues(bytes); } catch { for (let i = 0; i < bytes.length; i += 1) bytes[i] = Math.floor(Math.random() * 256); }
  return `ws-${Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("")}`;
}

async function call(path, method = "GET", body) {
  const init = { method, credentials: "omit", headers: { Accept: "application/json", "X-Workspace-Id": workspaceId() } };
  if (body !== undefined) { init.headers["Content-Type"] = "application/json"; init.body = JSON.stringify(body); }
  let res;
  try { res = await fetch(path, init); } catch { throw new Error("cannot reach the Token Workbench server"); }
  let data = null;
  try { data = await res.json(); } catch { /* not JSON */ }
  if (!res.ok) {
    const err = new Error(data?.message || data?.error || `HTTP ${res.status}`);
    err.status = res.status;
    err.data = data; // a failed Real call carries the trace of what was sent and answered
    throw err;
  }
  return data;
}

export const getHealth = () => call("/api/health");
export const getMeta = () => call("/api/meta");
export const getInfo = () => call("/api/info");
export const setMode = (source) => call("/api/mode", "POST", { source });
export const postReset = () => call("/api/reset", "POST");
export const postMint = (sample) => call("/api/mint", "POST", { sample });
export const postDecode = (token, verify) => call("/api/decode", "POST", { token, verify });
export const postIntrospect = (token) => call("/api/introspect", "POST", { token });
export const getTesterCases = () => call("/api/tester/cases");
export const postTesterRun = (caseId) => call("/api/tester/run", "POST", { case: caseId });
export const postCheckerRun = (body) => call("/api/checker/run", "POST", body);
export const getFlowCompare = () => call("/api/flows/compare");
export const postFlowRun = (mechanism, protectedFlag) => call("/api/flows/run", "POST", { mechanism, protected: protectedFlag });
