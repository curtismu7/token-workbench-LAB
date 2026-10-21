// Thin fetch wrapper. JSON in, JSON out. No credential headers, no cookies: the server refuses them. The token under
// test is DATA in a JSON body, never an Authorization header.
async function call(path, method = "GET", body) {
  const init = { method, credentials: "omit", headers: { Accept: "application/json" } };
  if (body !== undefined) { init.headers["Content-Type"] = "application/json"; init.body = JSON.stringify(body); }
  let res;
  try { res = await fetch(path, init); } catch { throw new Error("cannot reach the Token Workbench server"); }
  let data = null;
  try { data = await res.json(); } catch { /* not JSON */ }
  if (!res.ok) {
    const err = new Error(data?.message || data?.error || `HTTP ${res.status}`);
    err.status = res.status;
    throw err;
  }
  return data;
}

export const getHealth = () => call("/api/health");
export const getMeta = () => call("/api/meta");
export const postMint = (sample) => call("/api/mint", "POST", { sample });
export const postDecode = (token, verify) => call("/api/decode", "POST", { token, verify });
export const getTesterCases = () => call("/api/tester/cases");
export const postTesterRun = (caseId) => call("/api/tester/run", "POST", { case: caseId });
export const postCheckerRun = (body) => call("/api/checker/run", "POST", body);
export const getFlowCompare = () => call("/api/flows/compare");
export const postFlowRun = (mechanism, protectedFlag) => call("/api/flows/run", "POST", { mechanism, protected: protectedFlag });
