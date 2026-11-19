// Rule 24: every JSON the workbench shows goes through the shared JsonPane (Form | JSON, full view, important keys marked).
import React from "react";
import { cleanup, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import App from "./App.jsx";
import Trace from "./components/Trace.jsx";
import { setJsonView } from "./components/JsonPane.jsx";
import { CASES, COMPARE, HEALTH, META, caseResult, decoded, fakeToken, stubFetch } from "./test/fixtures.js";

const base = {
  "GET /api/health": HEALTH,
  "GET /api/meta": META,
  "GET /api/tester/cases": { cases: CASES },
  "GET /api/flows/compare": COMPARE,
};
beforeEach(() => setJsonView("form"));
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

describe("decode tab", () => {
  it("shows the decoded token as Header / Payload / Signature panes (Rule 24b) and the claims as Form | JSON panes", async () => {
    const claims = [
      { name: "alg", value: "ES256", meaning: "The signature algorithm.", level: "info" },
      { name: "act", value: { sub: "agent-7" }, meaning: "The actor.", level: "info" },
    ];
    stubFetch({ ...base, "POST /api/decode": decoded({ claims, header: { alg: "ES256", kid: "k1" }, payload: { sub: "u", act: { sub: "agent-7" }, exp: 4102444800 } }) });
    render(<App />);
    await userEvent.type(screen.getByLabelText("Token (JWT)"), fakeToken());
    await userEvent.click(screen.getByRole("button", { name: "Decode" }));
    // TokenParts renders Header / Payload / Signature headings with standard panes; the payload pane keeps decoded-token.
    const payload = await screen.findByTestId("decoded-token");
    const section = payload.closest(".card");
    for (const h of ["Header", "Payload", "Signature"]) expect(within(section).getByText(h)).toBeTruthy();
    expect(section).toHaveTextContent("ES256");
    expect(section).toHaveTextContent("agent-7");

    // an object claim value (act) is a pane with the Form | JSON toggle, not compact JSON text in a <code>
    const act = screen.getByRole("group", { name: "Claim act view" });
    expect(within(act).getAllByRole("button").map((b) => b.textContent)).toEqual(["Form", "JSON"]);
    expect([...document.querySelectorAll("table code")].some((c) => c.textContent.includes('{"sub"'))).toBe(false);

    // the raw header and payload: Form first, then the exact JSON text with the alg key stood out
    const raw = screen.getByTestId("decoded-json");
    expect(raw.querySelector("dl")).not.toBeNull();
    await userEvent.click(screen.getAllByRole("button", { name: "JSON" })[0]);
    const pane = screen.getByTestId("decoded-json");
    expect(pane.tagName).toBe("PRE");
    expect(pane).toHaveTextContent('"alg": "ES256"');
    expect(pane.querySelector(".jtok--hot")).not.toBeNull();
  });
});

describe("wrong-token tester tab", () => {
  it("shows the token sent in three colors, and plain text when no token was sent", async () => {
    stubFetch({ ...base, "POST /api/tester/run": { results: [caseResult("good"), caseResult("wrong-scope", { token: null })], summary: { total: 2, passed: 2, failed: 0 } } });
    render(<App />);
    await userEvent.click(screen.getByRole("button", { name: "Wrong-token tester" }));
    await screen.findByText("Wrong scope");
    await userEvent.click(screen.getByRole("button", { name: /Run all/ }));
    await screen.findByTestId("tester-summary");
    const sent = within(screen.getByTestId("detail-good")).getByLabelText("Token sent: Correct token (control)");
    expect(sent.querySelectorAll(".jtok--jwt1, .jtok--jwt2, .jtok--jwt3")).toHaveLength(3);
    const none = within(screen.getByTestId("detail-wrong-scope")).getByLabelText("Token sent: Wrong scope");
    expect(none).toHaveTextContent("(no token was sent)");
    expect(none.querySelector(".jtok")).toBeNull();
  });
});

describe("trace (Real operations)", () => {
  const TRACE = [
    { step: "discovery", method: "GET", url: "https://idp.example/as/.well-known/openid-configuration", status: 200, request: { headers: { accept: "application/json" }, body: null }, response: { headers: { "content-type": "application/json" }, body: '{"issuer":"https://idp.example/as","jwks_uri":"https://idp.example/as/jwks"}' } },
    { step: "token (client_credentials)", method: "POST", url: "https://idp.example/as/token", status: 200, request: { headers: { authorization: "Basic [client secret: write-only, not shown]" }, body: "grant_type=client_credentials" }, response: { headers: {}, body: '{"access_token":"x","token_type":"Bearer"}' } },
  ];

  it("keeps the HTTP headers as text and gives a JSON body its own Form | JSON pane; a form-encoded request stays text", () => {
    render(<Trace entries={TRACE} />);
    expect(screen.getByLabelText("Response 1 headers")).toHaveTextContent("content-type: application/json");
    const body = screen.getByRole("group", { name: "Response 1 body view" });
    expect(within(body).getAllByRole("button").map((b) => b.textContent)).toEqual(["Form", "JSON"]);
    expect(screen.getByRole("group", { name: "Response 2 body view" })).toBeInTheDocument();
    expect(screen.getByLabelText("Request 2")).toHaveTextContent("grant_type=client_credentials");
    expect(screen.queryByRole("group", { name: "Request 2 view" })).toBeNull();
  });
});
