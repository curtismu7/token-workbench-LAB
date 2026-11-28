import React from "react";
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import App, { TABS } from "./App.jsx";
import { workspaceId } from "./lib/api.js";
import { CASES, COMPARE, HEALTH, META, flowRun, stubFetch } from "./test/fixtures.js";

const BANNER = "HOSTED SIMULATION: this is a shared hosted demo. Every stub server, key and token here is simulated.";
const routes = (meta) => ({
  "GET /api/health": HEALTH,
  "GET /api/meta": meta,
  "GET /api/tester/cases": { cases: CASES },
  "GET /api/flows/compare": COMPARE,
  "POST /api/flows/run": (b) => flowRun(b.mechanism, b.protected),
});
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

describe("hosted build (MODE=se-mock)", () => {
  it("shows no banner element in the hosted or the local build (the Real-or-mock modal says it; see Modal.test.jsx), and no modal when the page is pre-dismissed", async () => {
    stubFetch(routes({ ...META, hosted: true, deployMode: "se-mock", banner: BANNER }));
    render(<App />);
    await screen.findByTestId("mode-badge");
    await new Promise((r) => { setTimeout(r, 20); });
    expect(screen.queryByTestId("hosted-banner")).toBeNull();
    expect(document.querySelector(".banner.hosted")).toBeNull();
    for (const [, label] of TABS) {
      // The TopMenu talk-track toggle shares the "Talk track" name; tabs are the buttons in the nav.
      const tabsNav = screen.getByRole("navigation", { name: "Tools" });
      await userEvent.click([...tabsNav.querySelectorAll("button")].find((b) => b.textContent === label));
      expect(screen.queryByTestId("hosted-banner")).toBeNull();
    }
  });
});

describe("workspace id", () => {
  it("is one valid id per tab, reused, and sent as X-Workspace-Id on every request", async () => {
    const calls = stubFetch(routes(META));
    render(<App />);
    await screen.findByTestId("mode-badge");
    await new Promise((r) => { setTimeout(r, 20); });
    const id = workspaceId();
    expect(id).toMatch(/^[a-z0-9][a-z0-9-]{0,31}$/);
    expect(workspaceId()).toBe(id);
    expect(calls.length).toBeGreaterThan(0);
    for (const c of calls) expect(c.init.headers["X-Workspace-Id"]).toBe(id);
  });

  it("still works when sessionStorage is blocked", () => {
    const orig = Object.getOwnPropertyDescriptor(window, "sessionStorage");
    Object.defineProperty(window, "sessionStorage", { configurable: true, get() { throw new Error("blocked"); } });
    try { expect(workspaceId()).toMatch(/^ws-[0-9a-f]{16}$/); expect(workspaceId()).toBe(workspaceId()); } finally { Object.defineProperty(window, "sessionStorage", orig); }
  });
});

describe("hosted profile checker", () => {
  it("offers no loopback URL option and does not say nothing leaves the machine", async () => {
    stubFetch(routes({ ...META, hosted: true, banner: BANNER }));
    render(<App />);
    await userEvent.click(await screen.findByRole("button", { name: "Profile checker" }));
    expect(screen.queryByLabelText(/loopback url/i)).toBeNull();
    expect(screen.queryByText(/A loopback URL/)).toBeNull();
    expect(screen.queryByText(/nothing leaves this machine/)).toBeNull();
  });
  it("keeps the loopback option in the local build", async () => {
    stubFetch(routes({ ...META, hosted: false, banner: null }));
    render(<App />);
    await userEvent.click(await screen.findByRole("button", { name: "Profile checker" }));
    expect(await screen.findByText(/A loopback URL/)).toBeTruthy();
  });
});
