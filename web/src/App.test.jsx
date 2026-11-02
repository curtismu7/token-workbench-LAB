import React from "react";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import fs from "node:fs";
import path from "node:path";
import App from "./App.jsx";
import { CASES, CHECK, COMPARE, EVIL, HEALTH, META, caseResult, decoded, fakeToken, flowRun, stubFetch } from "./test/fixtures.js";

const base = {
  "GET /api/health": HEALTH,
  "GET /api/meta": META,
  "GET /api/tester/cases": { cases: CASES },
  "GET /api/flows/compare": COMPARE,
  "POST /api/flows/run": (b) => flowRun(b.mechanism, b.protected),
};
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

describe("shell", () => {
  it("shows the DEMO badge, four tabs and the story strip, and switches tabs", async () => {
    stubFetch(base);
    render(<App />);
    expect(screen.getByTestId("mode-badge")).toHaveTextContent("DEMO");
    for (const n of ["Decode / Trace", "Wrong-token tester", "Profile checker", "Flow catalog"]) expect(screen.getByRole("button", { name: n })).toBeInTheDocument();
    expect(screen.getByRole("region", { name: /what each tab proves/i })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Profile checker" }));
    expect(screen.getByRole("heading", { name: "OAuth profile checker" })).toBeVisible();
    expect(screen.getByRole("button", { name: "Profile checker" })).toHaveAttribute("aria-pressed", "true");
  });

  it("toggles dark and light on the document element", async () => {
    stubFetch(base);
    render(<App />);
    const before = document.documentElement.dataset.theme;
    await userEvent.click(screen.getByRole("button", { name: /switch to (dark|light) theme/i }));
    expect(document.documentElement.dataset.theme).not.toBe(before);
  });

  it("warns when the API is unreachable", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => { throw new Error("down"); }));
    render(<App />);
    expect(await screen.findByText(/Cannot reach the Token Workbench API/)).toBeInTheDocument();
  });

  it("sends JSON bodies and never a credential header or cookie", async () => {
    const calls = stubFetch({ ...base, "POST /api/decode": decoded() });
    render(<App />);
    await userEvent.type(screen.getByLabelText("Token (JWT)"), fakeToken());
    await userEvent.click(screen.getByRole("button", { name: "Decode" }));
    await screen.findByTestId("decode-result");
    const post = calls.find((c) => c.method === "POST" && c.path === "/api/decode");
    expect(post.init.credentials).toBe("omit");
    expect(Object.keys(post.init.headers).map((h) => h.toLowerCase()).sort()).toEqual(["accept", "content-type", "x-workspace-id"]); // the workspace label is the only addition; it is not a credential
    expect(JSON.parse(post.init.body)).toEqual({ token: fakeToken(), verify: false });
    for (const c of calls) expect(Object.keys(c.init.headers || {}).some((h) => /authorization|cookie|dpop/i.test(h))).toBe(false);
  });
});

describe("decode tab", () => {
  it("explains claims, says cnf is decoded and not enforced, and renders hostile strings as text", async () => {
    stubFetch({ ...base, "POST /api/decode": decoded() });
    const { container } = render(<App />);
    await userEvent.type(screen.getByLabelText("Token (JWT)"), fakeToken());
    await userEvent.click(screen.getByRole("button", { name: "Decode" }));
    const res = await screen.findByTestId("decode-result");
    expect(res).toHaveTextContent("Signature NOT checked");
    expect(screen.getByTestId("cnf-note")).toHaveTextContent(/decoded, not enforced/i);
    expect(screen.getByTestId("cnf-note")).toHaveTextContent(/does not check a DPoP proof/i);
    expect(screen.getByText("The subject: who the token is about.")).toBeInTheDocument();
    expect(screen.getAllByText(EVIL).length).toBeGreaterThan(0);
    expect(container.querySelector("img")).toBeNull();
    expect(screen.getByTestId("countdown")).toHaveTextContent(/Expires in/);
    expect(screen.getByTestId("live")).toHaveTextContent(/Decoded: 4 claims/);
  });

  it("shows expired tokens and an invalid signature in words", async () => {
    stubFetch({ ...base, "POST /api/decode": decoded({ time: { hasExp: true, expired: true, secondsToExpiry: -3600, notYetValid: false }, signature: { state: "invalid", note: "does not verify" } }) });
    render(<App />);
    await userEvent.type(screen.getByLabelText("Token (JWT)"), "a.b.c");
    await userEvent.click(screen.getByRole("button", { name: "Decode" }));
    expect(await screen.findByText("Signature INVALID")).toBeInTheDocument();
    expect(screen.getByTestId("countdown")).toHaveTextContent("Expired 1h 0m ago");
  });

  it("mints a sample, fills the box and decodes it", async () => {
    const calls = stubFetch({ ...base, "POST /api/mint": { sample: "dpop", token: fakeToken() }, "POST /api/decode": decoded() });
    render(<App />);
    await userEvent.click(screen.getByRole("button", { name: "DPoP-bound" }));
    await screen.findByTestId("decode-result");
    expect(screen.getByLabelText("Token (JWT)")).toHaveValue(fakeToken());
    expect(calls.some((c) => c.path === "/api/mint")).toBe(true);
  });

  it("shows the server's refusal for a token that is not a JWT", async () => {
    stubFetch({ ...base, "POST /api/decode": { __status: 400, body: { error: "not_a_jwt", message: "header is not base64url JSON." } } });
    render(<App />);
    await userEvent.type(screen.getByLabelText("Token (JWT)"), "nope");
    await userEvent.click(screen.getByRole("button", { name: "Decode" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("header is not base64url JSON.");
  });
});

describe("wrong-token tester tab", () => {
  it("runs all cases and shows expected vs actual, the challenge, the rejecting check and a lesson", async () => {
    stubFetch({ ...base, "POST /api/tester/run": { results: [caseResult("good"), caseResult("wrong-scope", { pass: false })], summary: { total: 2, passed: 1, failed: 1 } } });
    render(<App />);
    await userEvent.click(screen.getByRole("button", { name: "Wrong-token tester" }));
    await screen.findByText("Wrong scope");
    await userEvent.click(screen.getByRole("button", { name: /Run all/ }));
    await screen.findByTestId("tester-summary");
    expect(screen.getByTestId("tester-summary")).toHaveTextContent("1 of 2 correct");
    const row = document.querySelector('tr[data-case="wrong-scope"]');
    expect(within(row).getByText("FAIL")).toBeInTheDocument();
    expect(row).toHaveTextContent("403 | insufficient_scope | rejected by: scope");
    const good = document.querySelector('tr[data-case="good"]');
    expect(within(good).getByText("PASS")).toBeInTheDocument();
    const detail = screen.getByTestId("detail-wrong-scope");
    expect(detail).toHaveTextContent('Bearer error="insufficient_scope"');
    expect(detail).toHaveTextContent("has the required scope: REJECTED HERE");
    expect(screen.getByText("Genuine token, missing permission.")).toBeInTheDocument();
    expect(screen.getByTestId("live")).toHaveTextContent("1 of 2 cases answered correctly");
  });

  it("tells the user when the run queue is full", async () => {
    stubFetch({ ...base, "POST /api/tester/run": { __status: 429, body: { error: "run_queue_full", message: "busy" } } });
    render(<App />);
    await userEvent.click(screen.getByRole("button", { name: "Wrong-token tester" }));
    await userEvent.click(screen.getByRole("button", { name: /Run all/ }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/Another run is in progress/);
  });
});

describe("profile checker tab", () => {
  it("runs a stub profile; FAPI is badged UNVERIFIED and each rule says pass or fail with evidence", async () => {
    const calls = stubFetch({ ...base, "POST /api/checker/run": CHECK });
    render(<App />);
    await userEvent.click(screen.getByRole("button", { name: "Profile checker" }));
    await userEvent.click(await screen.findByRole("radio", { name: /No PKCE/ }));
    await userEvent.click(screen.getByRole("button", { name: "Run checker" }));
    await screen.findByTestId("checker-result");
    expect(JSON.parse(calls.find((c) => c.path === "/api/checker/run").init.body)).toEqual({ profile: "no-pkce", pack: "both" });
    const fapi = screen.getByTestId("pack-fapi");
    expect(within(fapi).getByText("UNVERIFIED")).toBeInTheDocument();
    expect(screen.getByTestId("fapi-note")).toHaveTextContent(/simplified reading/);
    expect(within(screen.getByTestId("pack-bcp")).queryByText("UNVERIFIED")).toBeNull();
    const rule = document.querySelector('tr[data-rule="pkce-required"]');
    expect(rule).toHaveTextContent("FAIL");
    expect(rule).toHaveTextContent("issued a code with no challenge");
    expect(document.querySelector('tr[data-rule="metadata"]')).toHaveTextContent("PASS");
  });

  it("sends a loopback URL as target, and shows the server's refusal of anything else", async () => {
    const calls = stubFetch({ ...base, "POST /api/checker/run": { __status: 400, body: { error: "target_refused", message: "only loopback targets are allowed" } } });
    render(<App />);
    await userEvent.click(screen.getByRole("button", { name: "Profile checker" }));
    await userEvent.click(await screen.findByRole("radio", { name: /loopback URL/ }));
    await userEvent.type(screen.getByLabelText("Loopback URL"), "http://example.com");
    await userEvent.click(screen.getByRole("button", { name: "Run checker" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("only loopback targets are allowed");
    expect(JSON.parse(calls.find((c) => c.path === "/api/checker/run").init.body)).toEqual({ target: "http://example.com", pack: "both" });
  });
});

describe("flow catalog tab", () => {
  it("is badged SIMULATION, compares with and without, and Simulate walks the steps then Reset clears them", async () => {
    stubFetch(base);
    render(<App />);
    await userEvent.click(screen.getByRole("button", { name: "Flow catalog" }));
    expect(screen.getByText("SIMULATION")).toBeInTheDocument();
    expect(await screen.findByTestId("compare")).toHaveTextContent("ATTACK SUCCEEDS");
    expect(await screen.findByTestId("side-on")).toHaveTextContent("ATTACK BLOCKED");
    expect(screen.getByTestId("side-off")).toHaveTextContent("ATTACK SUCCEEDS");
    const caption = screen.getByTestId("caption");
    await userEvent.selectOptions(screen.getByLabelText("Speed"), "4");
    await userEvent.click(screen.getByRole("button", { name: "Simulate" }));
    await waitFor(() => expect(caption).toHaveTextContent("Step 1 of 2"));
    await waitFor(() => expect(caption).toHaveTextContent(/Attack blocked: refused/), { timeout: 3000 });
    await userEvent.click(screen.getByRole("button", { name: "Reset" }));
    expect(caption).toHaveTextContent("Press Simulate");
  });

  it("picks another mechanism from the table", async () => {
    const calls = stubFetch(base);
    render(<App />);
    await userEvent.click(screen.getByRole("button", { name: "Flow catalog" }));
    await userEvent.click(await screen.findByRole("button", { name: "PKCE" }));
    await waitFor(() => expect(calls.some((c) => c.path === "/api/flows/run" && JSON.parse(c.init.body).mechanism === "pkce")).toBe(true));
  });
});

describe("theme tokens", () => {
  it("use no purple: every hex colour in the shared stylesheet and app.css has a hue outside 255-320 degrees (or is grey)", () => {
    const css = ["standalone-ui.css", "app.css"].map((f) => fs.readFileSync(path.resolve(__dirname, f), "utf8")).join("\n");
    const hexes = [...new Set(css.match(/#[0-9a-f]{6}\b/gi))];
    expect(hexes.length).toBeGreaterThan(10);
    for (const h of hexes) {
      const [r, g, b] = [1, 3, 5].map((i) => parseInt(h.slice(i, i + 2), 16) / 255);
      const max = Math.max(r, g, b); const min = Math.min(r, g, b); const d = max - min;
      if (d < 0.06) continue;
      let hue = max === r ? ((g - b) / d) % 6 : max === g ? (b - r) / d + 2 : (r - g) / d + 4;
      hue = (hue * 60 + 360) % 360;
      expect(hue < 255 || hue > 320, `${h} hue ${Math.round(hue)}`).toBe(true);
    }
  });
});
