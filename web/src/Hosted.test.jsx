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

describe("hosted and simulated banner (MODE=se-mock)", () => {
  it("shows the server's banner above every tab, and keeps it when switching tabs", async () => {
    stubFetch(routes({ ...META, hosted: true, deployMode: "se-mock", banner: BANNER }));
    render(<App />);
    expect(await screen.findByTestId("hosted-banner")).toHaveTextContent(BANNER);
    for (const [, label] of TABS) {
      await userEvent.click(screen.getByRole("button", { name: label }));
      expect(screen.getByTestId("hosted-banner")).toHaveTextContent(/^HOSTED SIMULATION/);
    }
  });

  it("shows no hosted banner in the local build, or when the meta call fails", async () => {
    stubFetch(routes({ ...META, hosted: false, deployMode: "local", banner: null }));
    render(<App />);
    await screen.findByTestId("mode-badge");
    await new Promise((r) => { setTimeout(r, 20); });
    expect(screen.queryByTestId("hosted-banner")).toBeNull();
    cleanup();
    stubFetch({ "GET /api/health": HEALTH });
    render(<App />);
    await new Promise((r) => { setTimeout(r, 20); });
    expect(screen.queryByTestId("hosted-banner")).toBeNull();
  });

  it("renders the banner text as text, never as HTML", async () => {
    stubFetch(routes({ ...META, hosted: true, banner: "<img src=x onerror=alert(1)> hosted" }));
    const { container } = render(<App />);
    expect(await screen.findByTestId("hosted-banner")).toHaveTextContent("<img src=x onerror=alert(1)> hosted");
    expect(container.querySelector("img")).toBeNull();
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
