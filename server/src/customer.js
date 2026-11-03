// customer.config (rule 12) as the page sees it: a display name and tagline, renamed cast
// members and vocabulary overrides laid over the story text. No real customer names: the
// values come from a config file the operator supplies, never from the demo data.
// Shape mirrors the family standard (privilege-demo web/src/customer.js).
import fs from 'node:fs';

export const DEFAULT_CUSTOMER = {
  name: 'Hostile MCP LAB',
  tagline: 'The tool list changed overnight',
  cast: {},        // { [castId]: "Display Name" } — overrides vertical.cast names in the story panel
  vocabulary: {},  // { [term]: "Replacement" } — overrides vertical.vocab in the story panel
  warnings: [],
};

const STR = (v, max) => (typeof v === 'string' && v.length > 0 && v.length <= max ? v : null);
const MAP = (v, maxEntries) => {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return null;
  const out = {};
  for (const [k, val] of Object.entries(v)) {
    if (typeof k !== 'string' || k.length > 40) return null;
    const s = STR(val, 80);
    if (!s) return null;
    out[k] = s;
    if (Object.keys(out).length > maxEntries) return null;
  }
  return out;
};

/** Validate a customer object; null means "keep the defaults". Never throws. */
export function sanitizeCustomer(c) {
  if (!c || typeof c !== 'object' || Array.isArray(c)) return null;
  const out = {};
  const name = STR(c.name, 60);
  if (name) out.name = name;
  const tagline = STR(c.tagline, 120);
  if (tagline) out.tagline = tagline;
  const cast = MAP(c.cast, 30);
  if (cast) out.cast = cast;
  const vocabulary = MAP(c.vocabulary, 60);
  if (vocabulary) out.vocabulary = vocabulary;
  return Object.keys(out).length ? out : null;
}

/**
 * Read the operator's customer.config.json (path from CUSTOMER_CONFIG, else
 * <repo>/customer.config.json; missing or invalid means the defaults). Read at
 * startup only, never written, and only the fields above are ever served.
 */
export function loadCustomer({ path: explicit, root } = {}) {
  const p = explicit || process.env.CUSTOMER_CONFIG || (root ? `${root}/customer.config.json` : null);
  if (!p) return { ...DEFAULT_CUSTOMER };
  try {
    const raw = JSON.parse(fs.readFileSync(p, 'utf8'));
    const customer = sanitizeCustomer(raw.customer ?? raw);
    return { ...DEFAULT_CUSTOMER, ...(customer ?? {}), warnings: customer ? [] : ['customer.config.json was present but invalid; defaults are in use'] };
  } catch {
    return { ...DEFAULT_CUSTOMER, warnings: ['customer.config.json could not be read; defaults are in use'] };
  }
}
