// The Real-or-mock modal (shared/mode-modal) in the page: MOCK, REAL with the issuer, the hosted line, the wait for /api/meta and /api/info, and no banner.
import React from "react";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import App, { MODE_LINES } from "./App.jsx";
import { CASES, COMPARE, HEALTH, META, stubFetch } from "./test/fixtures.js";

const SETTINGS = [{ name: "TW_REAL", required: true, about: "set to 1 to opt in to Real" }];
const realView = (over = {}) => ({ available: true, optedIn: true, issuer: "https://idp.example/as", issuerOrigin: "https://idp.example", tokenAuth: "client_secret_basic", settings: SETTINGS, missing: [], problems: [], howTo: "x", ...over });
const INFO_REAL = { mode: "local", hosted: false, source: "real", realAvailable: true, real: realView() };
const INFO_MOCK = { mode: "local", hosted: false, source: "mock", realAvailable: true, real: realView() };
const INFO_HOSTED = { mode: "se-mock", hosted: true, source: "mock", realAvailable: false, real: null };
const BANNER = "HOSTED SIMULATION: this is a shared hosted demo.";
const base = (info, meta = META) => ({ "GET /api/health": HEALTH, "GET /api/meta": meta, "GET /api/info": info, "GET /api/tester/cases": { cases: CASES }, "GET /api/flows/compare": COMPARE });

beforeEach(() => sessionStorage.clear());
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

// Hold one API answer on a promise so a test can look at the page before it arrives.
function hold(path) {
  const inner = globalThis.fetch;
  let release; const gate = new Promise((r) => { release = r; });
  globalThis.fetch = (p, i) => (p === path ? gate.then(() => inner(p, i)) : inner(p, i));
  return release;
}

describe("Real-or-mock modal", () => {
  it("opens on MOCK with the stub line, and the old MOCK banner is gone", async () => {
    stubFetch(base(INFO_MOCK));
    render(<App />);
    const m = await screen.findByTestId("mode-modal");
    expect(m).toHaveAttribute("data-mode", "mock");
    expect(m).toHaveTextContent(/^MOCK/);
    expect(m).toHaveTextContent(MODE_LINES.mock);
    expect(m).toHaveTextContent(/Nothing real is contacted/);
    expect(screen.queryByTestId("mode-banner")).toBeNull();
    expect(document.querySelector(".banner")).toBeNull();
  });

  it("closes on Got it and stays closed after a same-session reload", async () => {
    stubFetch(base(INFO_MOCK));
    const first = render(<App />);
    await userEvent.click(await screen.findByTestId("mode-modal-ok"));
    expect(screen.queryByTestId("mode-modal")).toBeNull();
    first.unmount();
    render(<App />);
    await screen.findByTestId("mode-badge");
    await new Promise((r) => { setTimeout(r, 30); });
    expect(screen.queryByTestId("mode-modal")).toBeNull();
  });

  it("opens on REAL naming the one issuer and what stays stubbed; it waits for /api/info, so MOCK never flashes first", async () => {
    stubFetch(base(INFO_REAL));
    const release = hold("/api/info");
    render(<App />);
    await new Promise((r) => { setTimeout(r, 30); });
    expect(screen.queryByTestId("mode-modal")).toBeNull();
    release();
    const m = await screen.findByTestId("mode-modal");
    expect(m).toHaveAttribute("data-mode", "real");
    expect(m).toHaveTextContent(/^REAL/);
    expect(m).toHaveTextContent("https://idp.example");
    expect(m).toHaveTextContent(/nothing else/);
    expect(m).toHaveTextContent(/treat this screen as sensitive/);
    expect(m).toHaveTextContent(/tester and the flow catalog still use the in-process stubs/);
    expect(screen.queryByTestId("mode-banner")).toBeNull();
  });

  it("switching Mock to Real shows REAL even though MOCK was dismissed", async () => {
    stubFetch({ ...base(INFO_MOCK), "POST /api/mode": (b) => ({ ...INFO_REAL, source: b.source }) });
    render(<App />);
    await userEvent.click(await screen.findByTestId("mode-modal-ok"));
    await userEvent.selectOptions(screen.getByTestId("mode-select"), "real");
    const m = await screen.findByTestId("mode-modal");
    expect(m).toHaveAttribute("data-mode", "real");
    expect(m).toHaveTextContent("https://idp.example");
  });

  it("hosted build: MOCK with the HOSTED SIMULATION line (client-side), waiting for /api/meta, no server banner element", async () => {
    stubFetch(base(INFO_HOSTED, { ...META, hosted: true, deployMode: "se-mock", banner: BANNER }));
    const release = hold("/api/meta");
    render(<App />);
    await new Promise((r) => { setTimeout(r, 30); });
    expect(screen.queryByTestId("mode-modal")).toBeNull();
    release();
    const m = await screen.findByTestId("mode-modal");
    expect(m).toHaveAttribute("data-mode", "mock");
    expect(m).toHaveTextContent(MODE_LINES.hosted);
    expect(m).toHaveTextContent(/^MOCKHOSTED SIMULATION/);
    expect(m).toHaveTextContent(/private to your browser tab/);
    expect(m).toHaveTextContent(/Nothing real is contacted and you cannot point it at anything/);
    expect(screen.queryByTestId("hosted-banner")).toBeNull();
  });

  it("a dismissal in the local build does not hide the hosted line (separate storage key)", async () => {
    sessionStorage.setItem("tw-mode-seen-mock", "1");
    stubFetch(base(INFO_HOSTED, { ...META, hosted: true, deployMode: "se-mock", banner: BANNER }));
    render(<App />);
    expect(await screen.findByTestId("mode-modal")).toHaveTextContent(/^MOCKHOSTED SIMULATION/);
  });

  it("when /api/meta fails the page reads as the local build, MOCK", async () => {
    stubFetch({ "GET /api/health": HEALTH, "GET /api/info": INFO_MOCK });
    render(<App />);
    const m = await screen.findByTestId("mode-modal");
    expect(m).toHaveTextContent(MODE_LINES.mock);
    await waitFor(() => expect(screen.getByTestId("mode-badge")).toBeInTheDocument());
  });
});
