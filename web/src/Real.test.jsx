// Rule 19, Real mode in the page: the honest "Real not configured" state, the REAL banner and badge, REAL-labelled tokens,
// the trace (live token flow log) with the secret only as a marker, the metadata-only checker and the stubs-only notes.
import React from "react";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import App from "./App.jsx";
import ModeToggle from "./components/ModeToggle.jsx";
import { CASES, COMPARE, HEALTH, META, decoded, fakeToken, stubFetch } from "./test/fixtures.js";

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

const SETTINGS = [
  { name: "TW_REAL", required: true, about: "set to 1 to opt in to Real" },
  { name: "TW_REAL_ISSUER", required: true, about: "the issuer URL" },
  { name: "TW_REAL_CLIENT_ID", required: true, about: "a client" },
  { name: "TW_REAL_CLIENT_SECRET", required: true, about: "write-only" },
  { name: "TW_REAL_SCOPE", required: false, about: "optional" },
  { name: "TW_REAL_TOKEN_AUTH", required: false, about: "optional" },
];
const HOWTO = "Real is configured in the .env file beside docker-compose.yml (repo root).";
const realView = (over = {}) => ({ available: true, optedIn: true, issuer: "https://idp.example/as", issuerOrigin: "https://idp.example", tokenAuth: "client_secret_basic", settings: SETTINGS, missing: [], problems: [], howTo: HOWTO, ...over });
const INFO_REAL = { mode: "local", hosted: false, source: "real", realAvailable: true, real: realView() };
const INFO_OFF = { mode: "local", hosted: false, source: "mock", realAvailable: false, real: realView({ available: false, optedIn: false, issuer: null, issuerOrigin: null, missing: ["TW_REAL", "TW_REAL_CLIENT_SECRET"], problems: ["TW_REAL is not set: Real is off until the owner opts in", "TW_REAL_CLIENT_SECRET is not set"] }) };
const MARK = "Basic [client secret: write-only, not shown]";
const TRACE = [
  { step: "discovery", method: "GET", url: "https://idp.example/as/.well-known/openid-configuration", status: 200, request: { headers: { accept: "application/json" }, body: null }, response: { headers: { "content-type": "application/json" }, body: '{"issuer":"https://idp.example/as"}' } },
  { step: "token (client_credentials)", method: "POST", url: "https://idp.example/as/token", status: 200, request: { headers: { authorization: MARK }, body: "grant_type=client_credentials" }, response: { headers: {}, body: '{"access_token":"x"}' } },
];
const base = (info) => ({ "GET /api/health": HEALTH, "GET /api/meta": META, "GET /api/info": info, "GET /api/tester/cases": { cases: CASES }, "GET /api/flows/compare": COMPARE });

describe("Real not configured", () => {
  it("the toggle's Real button is disabled and names exactly the missing settings", () => {
    render(<ModeToggle info={INFO_OFF} onSelect={() => {}} />);
    expect(screen.getByTestId("mode-real")).toBeDisabled();
    expect(screen.getByTestId("mode-real").title).toBe("Real is not configured. Set TW_REAL, TW_REAL_CLIENT_SECRET in the .env file beside docker-compose.yml, then restart the lab.");
  });

  it("the page shows the MOCK banner first and a 'Real not configured' card with every setting and what is missing", async () => {
    stubFetch(base(INFO_OFF));
    render(<App />);
    const card = await screen.findByTestId("real-status");
    expect(card).toHaveTextContent(/Real not configured/);
    for (const s of SETTINGS) expect(within(card).getByText(s.name)).toBeInTheDocument();
    const row = (n) => within(card).getByText(n).closest("tr");
    expect(row("TW_REAL_CLIENT_SECRET")).toHaveTextContent("missing or invalid");
    expect(row("TW_REAL_ISSUER")).toHaveTextContent("ok");
    expect(within(card).getByTestId("real-problems")).toHaveTextContent("TW_REAL_CLIENT_SECRET is not set");
    const banner = screen.getByTestId("mode-banner");
    expect(banner).toHaveTextContent(/^MOCK:/); expect(banner).not.toHaveAttribute("data-state");
    expect(document.body.querySelector(".banner")).toBe(banner);
    expect(screen.getByTestId("mode-badge")).toHaveTextContent("DEMO");
  });

  it("no Real card when Real is available or in the hosted build", async () => {
    stubFetch(base(INFO_REAL)); const { unmount } = render(<App />);
    await screen.findByText(/REAL: Decode/); expect(screen.queryByTestId("real-status")).toBeNull(); unmount();
    stubFetch(base({ mode: "se-mock", hosted: true, source: "mock", realAvailable: false, real: null }));
    render(<App />); await waitFor(() => expect(screen.getByTestId("mode-mock")).toHaveAttribute("aria-pressed", "true"));
    expect(screen.queryByTestId("real-status")).toBeNull();
  });
});

describe("Real mode", () => {
  it("live banner and REAL badge; minting gets a REAL token and shows the trace with the secret only as a marker", async () => {
    const calls = stubFetch({ ...base(INFO_REAL), "POST /api/mint": { source: "real", label: "REAL", sample: "client_credentials", token: fakeToken({ iss: "https://idp.example/as" }), trace: TRACE }, "POST /api/decode": decoded({ source: "real" }) });
    render(<App />);
    const banner = await screen.findByTestId("mode-banner");
    await waitFor(() => expect(banner).toHaveAttribute("data-state", "live"));
    expect(banner).toHaveTextContent("https://idp.example");
    expect(screen.getByTestId("mode-badge")).toHaveTextContent("REAL");
    expect(screen.queryByRole("button", { name: "DPoP-bound" })).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: "REAL client_credentials token" }));
    expect(await screen.findByTestId("token-label")).toHaveTextContent("REAL");
    expect(JSON.parse(calls.find((c) => c.path === "/api/mint").init.body)).toEqual({ sample: "client_credentials" });
    const trace = screen.getByTestId("trace");
    expect(within(trace).getAllByRole("listitem").map((li) => li.dataset.step)).toEqual(["discovery", "token (client_credentials)"]);
    expect(trace).toHaveTextContent(MARK);
    expect(screen.getByLabelText("Verify the signature against the issuer's real JWKS")).toBeInTheDocument();
  });

  it("a failed Real call shows the error and the trace of what was sent", async () => {
    stubFetch({ ...base(INFO_REAL), "POST /api/mint": { __status: 502, body: { error: "real_error", message: "the token endpoint answered 401 (invalid_client)", trace: [{ ...TRACE[1], status: 401 }] } } });
    render(<App />);
    await userEvent.click(await screen.findByRole("button", { name: "REAL client_credentials token" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("invalid_client");
    expect(screen.getByTestId("trace")).toHaveTextContent("HTTP 401");
  });

  it("introspection shows ACTIVE with the REAL label", async () => {
    stubFetch({ ...base(INFO_REAL), "POST /api/introspect": { source: "real", active: true, trace: TRACE.slice(0, 1) } });
    render(<App />);
    await screen.findByText(/REAL: Decode/);
    await userEvent.type(screen.getByLabelText("Token (JWT)"), "a.b.c");
    await userEvent.click(screen.getByRole("button", { name: "Introspect at the issuer" }));
    const r = await screen.findByTestId("introspect-result");
    expect(r).toHaveTextContent("ACTIVE"); expect(r).toHaveTextContent("REAL");
  });

  it("the checker reads the issuer's metadata: no stub choice, sends only pack, shows NOT CHECKED", async () => {
    const res = { source: "real", target: "https://idp.example/as", metadata: { found: true }, trace: TRACE.slice(0, 1), packs: { bcp: { title: "RFC 9700 BCP", unverified: false, note: "n", rules: [{ id: "pkce-required", title: "PKCE is required", rfc: "RFC 7636", why: "w", status: "not_checked", evidence: "not checked in Real: active probes" }] } } };
    const calls = stubFetch({ ...base(INFO_REAL), "POST /api/checker/run": res });
    render(<App />);
    await userEvent.click(screen.getByRole("button", { name: "Profile checker" }));
    expect(await screen.findByTestId("checker-real")).toHaveTextContent("https://idp.example/as");
    expect(screen.queryByRole("radio")).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: "Check the issuer's metadata" }));
    expect(await screen.findByText("NOT CHECKED")).toBeInTheDocument();
    expect(JSON.parse(calls.find((c) => c.path === "/api/checker/run").init.body)).toEqual({ pack: "both" });
  });

  it("the tester and the flow catalog say they have no Real version", async () => {
    stubFetch(base(INFO_REAL));
    render(<App />);
    await screen.findByText(/REAL: Decode/);
    await userEvent.click(screen.getByRole("button", { name: "Wrong-token tester" }));
    expect(screen.getAllByTestId("real-note").some((n) => n.checkVisibility?.() ?? true)).toBe(true);
    await userEvent.click(screen.getByRole("button", { name: "Flow catalog" }));
    expect(screen.getAllByTestId("real-note").length).toBeGreaterThanOrEqual(1);
  });

  it("switching Real -> Mock reloads the tabs: the REAL token and trace are gone and the stub samples are back", async () => {
    stubFetch({ ...base(INFO_REAL), "POST /api/mint": { source: "real", label: "REAL", token: fakeToken(), trace: TRACE }, "POST /api/decode": decoded(), "POST /api/mode": (b) => ({ ...INFO_REAL, source: b.source }) });
    render(<App />);
    await userEvent.click(await screen.findByRole("button", { name: "REAL client_credentials token" }));
    await screen.findByTestId("trace");
    await userEvent.click(screen.getByTestId("mode-mock"));
    await waitFor(() => expect(screen.getByTestId("mode-banner")).toHaveTextContent(/^MOCK:/));
    expect(screen.queryByTestId("trace")).toBeNull();
    expect(screen.queryByTestId("token-label")).toBeNull();
    expect(screen.getByLabelText("Token (JWT)")).toHaveValue("");
    expect(screen.getByRole("button", { name: "DPoP-bound" })).toBeInTheDocument();
    expect(screen.getByTestId("mode-badge")).toHaveTextContent("DEMO");
  });

  it("a mock token is labelled MOCK", async () => {
    stubFetch({ ...base({ ...INFO_REAL, source: "mock" }), "POST /api/mint": { source: "mock", label: "MOCK", token: fakeToken() }, "POST /api/decode": decoded() });
    render(<App />);
    await userEvent.click(await screen.findByRole("button", { name: "Agent token" }));
    expect(await screen.findByTestId("token-label")).toHaveTextContent("MOCK");
  });
});
