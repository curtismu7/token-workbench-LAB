import React from "react";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import App from "./App.jsx";
import { HEALTH, META, stubFetch } from "./test/fixtures.js";

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

// The lab's mode is a server-side fact (Real when the owner configured TW_REAL, Mock otherwise).
// There is no user-facing toggle: the page always shows the configured mode.
describe("mode is fixed by the server (no toggle)", () => {
  it("the header offers no Mock/Real selector", async () => {
    stubFetch({
      "GET /api/health": HEALTH, "GET /api/meta": META,
      "GET /api/info": { mode: "local", hosted: false, source: "real", realAvailable: true },
    });
    render(<App />);
    await waitFor(() => expect(screen.getByTestId("mode-badge")).toHaveTextContent("REAL"));
    expect(screen.queryByTestId("mode-select")).toBeNull();
  });

  it("mock-only build: the DEMO badge shows and there is still no selector", async () => {
    stubFetch({
      "GET /api/health": HEALTH, "GET /api/meta": META,
      "GET /api/info": { mode: "local", hosted: false, source: "mock", realAvailable: false },
    });
    render(<App />);
    await waitFor(() => expect(screen.getByTestId("mode-badge")).toHaveTextContent("DEMO"));
    expect(screen.queryByTestId("mode-select")).toBeNull();
  });
});
