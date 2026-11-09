// Customer Agent LAB hands a use case here with ?from=customer-agent&uc=<id>&vertical=<id> (read by the vendored return-link module).
// Preselect only where the catalog id obviously maps to one of this app's tabs; anything else opens the default tab (strip only).
// UC-LEARN17 (OAuth debug, live token flow log) also routes here; it has no tab of its own, so it opens the default Decode / Trace tab.
// This app has no verticals, so `vertical` is shown in the strip and not used.
export const UC_TAB = Object.freeze({ "UC-LEARN6": "flows" });
export const tabFor = (ctx) => (ctx && Object.hasOwn(UC_TAB, ctx.uc) ? UC_TAB[ctx.uc] : null);
