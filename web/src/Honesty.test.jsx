// TW2: pins for the honesty labels, the live regions, the keyboard reach and the colour contrast the review found unpinned.
// Each assertion was checked to fail when the text, attribute or colour it names is removed.
import React from "react";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import fs from "node:fs";
import path from "node:path";
import App from "./App.jsx";
import { CASES, CHECK, COMPARE, HEALTH, META, caseResult, decoded, fakeToken, flowRun, stubFetch } from "./test/fixtures.js";

const base = {
  "GET /api/health": HEALTH, "GET /api/meta": META, "GET /api/tester/cases": { cases: CASES }, "GET /api/flows/compare": COMPARE,
  "POST /api/flows/run": (b) => flowRun(b.mechanism, b.protected),
};
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });
const tab = (name) => userEvent.click(screen.getByRole("button", { name }));

describe("honesty labels", () => {
  it("the story strip says the FAPI pack is UNVERIFIED and the flows are a simulation of mechanisms, not of any product", () => {
    stubFetch(base);
    render(<App />);
    const strip = screen.getByRole("region", { name: /what each tab proves/i });
    expect(strip).toHaveTextContent("The FAPI 2.0 pack is UNVERIFIED.");
    expect(strip).toHaveTextContent("This is a simulation of the mechanisms, not of any product.");
    expect(strip).toHaveTextContent(/Fifteen wrong tokens/);
  });

  it("the DEMO badge explains itself to a screen reader", () => {
    stubFetch(base);
    render(<App />);
    expect(screen.getByTestId("mode-badge")).toHaveTextContent("DEMO: stub servers on loopback, nothing real is contacted");
  });

  it("the checker marks the FAPI-only choice UNVERIFIED, shows the RFC 9700 citation note, and the announcement names UNVERIFIED", async () => {
    stubFetch({ ...base, "POST /api/checker/run": CHECK });
    render(<App />);
    await tab("Profile checker");
    expect(screen.getByRole("option", { name: "FAPI 2.0 only (UNVERIFIED)" })).toBeInTheDocument();
    expect(screen.getByLabelText(/Rule pack/)).toBeInTheDocument();
    await userEvent.click(await screen.findByRole("radio", { name: /No PKCE/ }));
    await userEvent.click(screen.getByRole("button", { name: "Run checker" }));
    await screen.findByTestId("checker-result");
    expect(screen.getByTestId("bcp-note")).toHaveTextContent(/not section numbers/);
    const live = screen.getByTestId("live");
    expect(live).toHaveTextContent("RFC 9700 pack: 1 passed, 1 failed");
    expect(live).toHaveTextContent("FAPI 2.0 pack (UNVERIFIED): 0 passed, 1 failed");
  });

  it("the checker says so when the target did not answer", async () => {
    stubFetch({ ...base, "POST /api/checker/run": { ...CHECK, unreachable: true, metadata: { found: false } } });
    render(<App />);
    await tab("Profile checker");
    await userEvent.click(await screen.findByRole("radio", { name: /No PKCE/ }));
    await userEvent.click(screen.getByRole("button", { name: "Run checker" }));
    expect(await screen.findByText(/did not answer, so no rule was judged/)).toBeInTheDocument();
  });

  it("the tester explains PASS and announces a single case truthfully", async () => {
    stubFetch({ ...base, "POST /api/tester/run": (b) => ({ results: [caseResult(b.case, { pass: b.case === "good" })], summary: { total: 1, passed: 1, failed: 0 } }) });
    render(<App />);
    await tab("Wrong-token tester");
    expect(screen.getByText(/PASS means the stub gave the correct answer for that case/)).toBeInTheDocument();
    await userEvent.click(await screen.findByRole("button", { name: "Run case: Correct token (control)" }));
    await waitFor(() => expect(screen.getByTestId("live")).toHaveTextContent(/answered correctly\./));
    expect(screen.getByTestId("live")).not.toHaveTextContent(/incorrectly/);
    await userEvent.click(screen.getByRole("button", { name: "Run case: Wrong scope" }));
    await waitFor(() => expect(screen.getByTestId("live")).toHaveTextContent(/Wrong scope: answered incorrectly\./));
  });

  it("the decode tab says the workbench only reads and explains cnf", async () => {
    stubFetch({ ...base, "POST /api/decode": decoded() });
    render(<App />);
    await userEvent.type(screen.getByLabelText("Token (JWT)"), fakeToken());
    await userEvent.click(screen.getByRole("button", { name: "Decode" }));
    expect(await screen.findByTestId("cnf-note")).toHaveTextContent("This workbench only reads and explains cnf.");
  });

  it("the decode table lists claims the server returns that the workbench does not know", async () => {
    const claims = [...decoded().claims, { name: "name", value: "Ada", meaning: "A claim this workbench does not explain. Shown as the token carries it.", level: "info" }];
    stubFetch({ ...base, "POST /api/decode": decoded({ claims }) });
    render(<App />);
    await userEvent.type(screen.getByLabelText("Token (JWT)"), fakeToken());
    await userEvent.click(screen.getByRole("button", { name: "Decode" }));
    const row = (await screen.findByText("Ada")).closest("tr");
    expect(row).toHaveTextContent("A claim this workbench does not explain");
  });

  it("the flow catalog says it is a simulation that says nothing about any product, and shows the mechanism's limits", async () => {
    stubFetch(base);
    render(<App />);
    await tab("Flow catalog");
    expect(screen.getByText(/says nothing about how any product behaves/)).toBeInTheDocument();
    expect(await screen.findByText(/Limits of DPOP:/)).toBeInTheDocument();
    expect(screen.getByText(/DPOP limits\./)).toBeInTheDocument();
  });
});

describe("accessibility behaviour", () => {
  it("the live region is a polite status region, and a message from one tab is cleared when another opens", async () => {
    stubFetch({ ...base, "POST /api/checker/run": CHECK });
    render(<App />);
    const live = screen.getByTestId("live");
    expect(live).toHaveAttribute("role", "status");
    expect(live).toHaveAttribute("aria-live", "polite");
    await tab("Profile checker");
    await userEvent.click(await screen.findByRole("radio", { name: /No PKCE/ }));
    await userEvent.click(screen.getByRole("button", { name: "Run checker" }));
    await waitFor(() => expect(live).toHaveTextContent(/Profile checker\./));
    await tab("Flow catalog");
    expect(live).toHaveTextContent("");
    expect(live.textContent).toBe("");
  });

  it("only the selected tool is shown; the skip link is visible text that targets main", async () => {
    stubFetch(base);
    render(<App />);
    const hidden = (name) => screen.getByRole("heading", { name, hidden: true });
    expect(hidden("Decode and trace a token")).toBeVisible();
    expect(hidden("Wrong-token tester")).not.toBeVisible();
    expect(hidden("OAuth profile checker")).not.toBeVisible();
    await tab("Wrong-token tester");
    expect(hidden("Wrong-token tester")).toBeVisible();
    expect(hidden("Decode and trace a token")).not.toBeVisible();
    const skip = screen.getByText("Skip to content");
    expect(skip).toHaveAttribute("href", "#main");
    expect(skip).toBeVisible();
    expect(document.getElementById("main")).toHaveAttribute("tabindex", "-1");
  });

  it("every scrollable table region can be focused from the keyboard and has a name", async () => {
    stubFetch({ ...base, "POST /api/decode": decoded(), "POST /api/checker/run": CHECK });
    render(<App />);
    await userEvent.type(screen.getByLabelText("Token (JWT)"), fakeToken());
    await userEvent.click(screen.getByRole("button", { name: "Decode" }));
    await screen.findByTestId("decode-result");
    await tab("Profile checker");
    await userEvent.click(await screen.findByRole("radio", { name: /No PKCE/ }));
    await userEvent.click(screen.getByRole("button", { name: "Run checker" }));
    await screen.findByTestId("checker-result");
    await tab("Flow catalog");
    await screen.findByTestId("compare");
    const wraps = [...document.querySelectorAll(".table-wrap")];
    expect(wraps.length).toBeGreaterThanOrEqual(5);
    for (const w of wraps) {
      expect(w.getAttribute("tabindex")).toBe("0");
      expect(w.getAttribute("role")).toBe("region");
      expect(w.getAttribute("aria-label")).toMatch(/scrollable/);
    }
  });

  it("Simulate keeps keyboard focus while it runs (aria-disabled, not disabled), and a second press does nothing", async () => {
    const calls = stubFetch(base);
    render(<App />);
    await tab("Flow catalog");
    await screen.findByTestId("side-on");
    const sim = screen.getByRole("button", { name: "Simulate" });
    await userEvent.selectOptions(screen.getByLabelText("Speed"), "4");
    sim.focus();
    await userEvent.keyboard("{Enter}");
    expect(document.activeElement).toBe(sim);
    expect(sim).not.toBeDisabled();
    expect(sim).toHaveAttribute("aria-disabled", "true");
    const cap = screen.getByTestId("caption");
    expect(cap).toHaveAttribute("role", "status");
    expect(cap).toHaveAttribute("aria-live", "polite");
    const announced = () => screen.getByTestId("live").textContent;
    expect(announced()).toMatch(/Simulating DPOP with protection/);
    await userEvent.keyboard("{Enter}");
    expect(document.activeElement).toBe(sim);
    await waitFor(() => expect(sim).toHaveAttribute("aria-disabled", "false"), { timeout: 4000 });
    expect(document.activeElement).toBe(sim);
    expect(calls.length).toBeGreaterThan(0);
  });

  it("the flow page has no skipped heading level and its boxes have names", async () => {
    stubFetch(base);
    render(<App />);
    await tab("Flow catalog");
    await screen.findByTestId("side-on");
    const section = screen.getByRole("heading", { name: "Token-flow catalog" }).closest("section");
    const levels = [...section.querySelectorAll("h1,h2,h3,h4,h5,h6")].map((h) => Number(h.tagName[1]));
    expect(levels[0]).toBe(2);
    for (let i = 1; i < levels.length; i += 1) expect(levels[i] - levels[i - 1], `heading order ${levels}`).toBeLessThanOrEqual(1);
    expect(section.querySelector("h4")).toBeNull();
    const nodes = [...document.querySelectorAll(".react-flow__node")];
    expect(nodes.length).toBe(5);
    expect(nodes.map((n) => n.getAttribute("aria-label")).sort()).toEqual(["Attacker", "Authorization server", "Browser", "Client app", "Resource server"]);
    expect(within(section).getByRole("region", { name: /Diagram area/ })).toHaveAttribute("tabindex", "0");
  });
});

describe("colour contrast", () => {
  const css = fs.readFileSync(path.resolve(__dirname, "app.css"), "utf8");
  const block = (re) => Object.fromEntries([...css.match(re)[1].matchAll(/--([\w-]+):\s*(#[0-9a-f]{6})/gi)].map((m) => [m[1], m[2]]));
  const themes = { light: block(/:root \{([^}]*)\}/), dark: block(/:root\[data-theme="dark"\] \{([^}]*)\}/) };
  const lum = (h) => { const c = [1, 3, 5].map((i) => parseInt(h.slice(i, i + 2), 16) / 255).map((x) => (x <= 0.03928 ? x / 12.92 : ((x + 0.055) / 1.055) ** 2.4)); return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2]; };
  const ratio = (a, b) => { const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p); return (x + 0.05) / (y + 0.05); };
  const PAIRS = [["ok", "ok-wash"], ["hold", "hold-wash"], ["deny", "deny-wash"], ["info", "info-wash"], ["mute", "mute-wash"], ["text", "bg"], ["text", "card"], ["muted", "bg"], ["muted", "card"], ["on-accent", "accent"], ["accent", "card"], ["mark-text", "mark"], ["ok", "card"], ["deny", "card"], ["hold", "bg"]];
  for (const [name, t] of Object.entries(themes)) {
    it(`${name} theme: every text/background pair meets WCAG AA (4.5:1)`, () => {
      for (const [fg, bg] of PAIRS) expect(ratio(t[fg], t[bg]), `${name} --${fg} on --${bg}`).toBeGreaterThanOrEqual(4.5);
    });
  }
});
