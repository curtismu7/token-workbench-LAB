// Outbound target policy. The checker and the tester may contact loopback http hosts only. Remote targets are refused,
// not warned about: this tool sends deliberately malformed and hostile-looking requests (wrong redirect URIs,
// downgraded PKCE, password grants), which must never be aimed at a server somebody else runs.
import { isLoopbackHost } from './safety.js';

export function evaluateTarget(target) {
  let url;
  try { url = new URL(target); } catch { return { allowed: false, reason: 'invalid_url', normalizedUrl: null }; }
  if (url.protocol !== 'http:') return { allowed: false, reason: 'unsupported_scheme', normalizedUrl: null };
  if (url.username || url.password) return { allowed: false, reason: 'credentials_not_allowed', normalizedUrl: null };
  if (!isLoopbackHost(url.hostname)) return { allowed: false, reason: 'not_loopback', normalizedUrl: null };
  url.hash = '';
  return { allowed: true, reason: null, normalizedUrl: url.toString() };
}

export const REFUSAL_TEXT = {
  hosted_build: 'this hosted demo checks its built-in stub servers only; run the standalone build to point the checker at a loopback server of your own',
  invalid_url: 'not a valid URL',
  unsupported_scheme: 'only http:// loopback targets are allowed',
  credentials_not_allowed: 'a URL with a user name or password is refused',
  not_loopback: 'remote targets are refused: this tool only talks to loopback (127.x, ::1, localhost)',
};
