// Opened from Customer Agent LAB: the strip sits right below the banners (the hosted simulation banner stays first), a compact Back
// button sits in the header, and UC-LEARN6 opens the Flow catalog tab (handoffMap.js).
import React from "react";
import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import App, { TABS } from "./App.jsx";
import { UC_TAB, tabFor } from "./handoffMap.js";
import { CASES, COMPARE, HEALTH, META, flowRun, stubFetch } from "./test/fixtures.js";

const base = {
  "GET /api/health": HEALTH,
  "GET /api/meta": META,
  "GET /api/tester/cases": { cases: CASES },
  "GET /api/flows/compare": COMPARE,
  "POST /api/flows/run": (b) => flowRun(b.mechanism, b.protected),
};
const at = (url) => window.history.replaceState(null, "", url);
const pressed = () => screen.getAllByRole("button", { pressed: true }).filter((b) => b.classList.contains("tab")).map((b) => b.textContent);
afterEach(() => { cleanup(); vi.unstubAllGlobals(); at("/"); });

describe("hand-off from Customer Agent LAB", () => {
  it("every mapped use case names a real tab; odd ids map to nothing", () => {
    for (const t of Object.values(UC_TAB)) expect(TABS.map(([id]) => id)).toContain(t);
    expect(tabFor({ uc: "UC-LEARN17" })).toBeNull();
    expect(tabFor({ uc: "toString" })).toBeNull();
    expect(tabFor(null)).toBeNull();
  });

  it("UC-LEARN6: hosted banner then strip, header Back, the Flow catalog tab is open", async () => {
    stubFetch({ ...base, "GET /api/meta": { ...META, hosted: true, banner: "Hosted and simulated." } });
    at("/?from=customer-agent&uc=UC-LEARN6&vertical=banking");
    render(<App />);
    const strip = screen.getByRole("note", { name: "Opened from Customer Agent LAB" });
    expect(strip).toHaveTextContent("UC-LEARN6");
    const banner = await screen.findByTestId("hosted-banner");
    expect(banner.nextElementSibling).toBe(strip);
    expect(document.querySelector("header.top .top-menu button.return-link--header")).not.toBeNull();
    expect(pressed()).toEqual(["Flow catalog"]);
    expect(await screen.findByRole("heading", { name: "Token-flow catalog" })).toBeInTheDocument();
  });

  // The page's own path decides where Back goes: at / it is the app's own port (direct URL), under /token-workbench/ the lab proxy.
  for (const [pathname, href] of [["/", "http://127.0.0.1:5603/?returned=token-workbench&uc=UC-LEARN17"], ["/token-workbench/", "/customer-agent/?returned=token-workbench&uc=UC-LEARN17"]]) {
    it(`served at ${pathname}: Back goes to ${href}; UC-LEARN17 keeps the default tab (strip only)`, async () => {
      stubFetch(base);
      const assign = vi.fn();
      vi.stubGlobal("location", { ...window.location, pathname, search: "?from=customer-agent&uc=UC-LEARN17", assign });
      render(<App />);
      for (const b of screen.getAllByRole("button", { name: /Back to Customer Agent LAB/ })) fireEvent.click(b);
      expect(assign.mock.calls).toEqual([[href], [href]]);
      expect(pressed()).toEqual(["Decode / Trace"]);
      await waitFor(() => expect(screen.getByTestId("mode-badge")).toBeInTheDocument());
    });
  }

  it("hand-off from AI Demo Standalone: the strip renders and Back goes to /ai-demo-standalone/", async () => {
    stubFetch(base);
    const assign = vi.fn();
    vi.stubGlobal("location", { ...window.location, pathname: "/token-workbench/", search: "?from=ai-demo-standalone&uc=UC-LEARN17", assign });
    render(<App />);
    const strip = screen.getByRole("note", { name: "Opened from AI Demo Standalone" });
    expect(strip).toHaveTextContent("UC-LEARN17");
    for (const b of screen.getAllByRole("button", { name: /Back to AI Demo Standalone/ })) fireEvent.click(b);
    expect(assign.mock.calls).toEqual([["/ai-demo-standalone/?returned=token-workbench&uc=UC-LEARN17"], ["/ai-demo-standalone/?returned=token-workbench&uc=UC-LEARN17"]]);
    await waitFor(() => expect(screen.getByTestId("mode-badge")).toBeInTheDocument());
  });

  it("no from, an unknown from or a bad id: no strip, no button, default tab", () => {
    for (const q of ["/", "/?from=elsewhere&uc=UC-LEARN6", "/?from=customer-agent&uc=a%20b", "/?from=customer-agent&uc=UC-LEARN6&vertical=%3Cb%3E"]) {
      stubFetch(base);
      at(q);
      render(<App />);
      expect(screen.queryByRole("note", { name: /Opened from/ })).toBeNull();
      expect(screen.queryByRole("button", { name: /Back to/ })).toBeNull();
      expect(pressed()).toEqual(["Decode / Trace"]);
      cleanup();
    }
  });

  it("the vendored files match return-link.sha256, which names the parent commit", () => {
    const dir = path.join(process.cwd(), "src", "return-link");
    const text = fs.readFileSync(path.join(dir, "return-link.sha256"), "utf8");
    expect(text.split("\n")[0]).toMatch(/^# vendored byte for byte from curtismu7\/AI-DEMO-Standalone shared\/return-link at [0-9a-f]{7,40}/);
    const pins = text.split("\n").filter((l) => l && !l.startsWith("#")).map((l) => l.split(/\s+/));
    expect(pins.map(([, f]) => f).sort()).toEqual(["ReturnLink.jsx", "ReturnLink.test.jsx", "returnTargets.js"]);
    for (const [h, f] of pins) expect(createHash("sha256").update(fs.readFileSync(path.join(dir, f))).digest("hex"), f).toBe(h);
  });
});
