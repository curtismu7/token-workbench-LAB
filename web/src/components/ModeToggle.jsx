// Rule 19: the Mock / Real toggle. Real needs the owner's settings (TW_REAL=1 and the issuer and client in the lab's .env);
// until then Real is disabled and its tooltip names exactly what is missing. Switching goes through POST /api/mode.
const HOSTED = "The hosted build is Mock only.";
export const notConfiguredText = (real) => `Real is not configured. Set ${(real?.missing?.length ? real.missing : ["TW_REAL", "TW_REAL_ISSUER", "TW_REAL_CLIENT_ID", "TW_REAL_CLIENT_SECRET"]).join(", ")} in the .env file beside docker-compose.yml, then restart the lab.`;

export default function ModeToggle({ info, onSelect }) {
  const loading = !info;
  const source = info?.source;
  const hosted = info?.hosted === true;
  const realOff = loading || hosted || info?.realAvailable !== true;
  const pick = (next) => { if (next !== source) onSelect?.(next); };
  const title = hosted ? HOSTED : realOff && !loading ? notConfiguredText(info?.real) : undefined;
  return (
    <div className="mode-toggle" role="group" aria-label="Mode" data-testid="mode">
      <button type="button" aria-pressed={source === "mock"} disabled={loading} onClick={() => pick("mock")} data-testid="mode-mock">Mock</button>
      <button type="button" aria-pressed={source === "real"} disabled={realOff} title={title} onClick={() => pick("real")} data-testid="mode-real">Real</button>
    </div>
  );
}
