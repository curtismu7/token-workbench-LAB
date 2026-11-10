import React from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import App from "./App.jsx";
import ModeToggle from "./components/ModeToggle.jsx";
import { HEALTH, META, stubFetch } from "./test/fixtures.js";

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

describe("Mock/Real toggle (rule 19)", () => {
  it("local, Real not configured: Mock is pressed and Real is disabled naming the settings", () => {
    render(<ModeToggle info={{ mode: "local", hosted: false, source: "mock", realAvailable: false }} onSelect={() => {}} />);
    expect(screen.getByTestId("mode-mock")).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByTestId("mode-real")).toBeDisabled();
    expect(screen.getByTestId("mode-real")).toHaveAttribute("title", expect.stringMatching(/Real is not configured. Set TW_REAL, TW_REAL_ISSUER, TW_REAL_CLIENT_ID, TW_REAL_CLIENT_SECRET in the .env file beside docker-compose.yml/));
  });

  it("hosted: Real is disabled saying the hosted build is Mock only", () => {
    render(<ModeToggle info={{ mode: "se-mock", hosted: true, source: "mock", realAvailable: false }} onSelect={() => {}} />);
    expect(screen.getByTestId("mode-real")).toBeDisabled();
    expect(screen.getByTestId("mode-real")).toHaveAttribute("title", "The hosted build is Mock only.");
  });

  it("when Real is available the buttons switch both ways and the pressed one does nothing", () => {
    const picked = [];
    const { rerender } = render(<ModeToggle info={{ hosted: false, source: "mock", realAvailable: true }} onSelect={(s) => picked.push(s)} />);
    fireEvent.click(screen.getByTestId("mode-mock"));
    expect(picked).toEqual([]);
    fireEvent.click(screen.getByTestId("mode-real"));
    expect(picked).toEqual(["real"]);
    rerender(<ModeToggle info={{ hosted: false, source: "real", realAvailable: true }} onSelect={(s) => picked.push(s)} />);
    fireEvent.click(screen.getByTestId("mode-mock"));
    expect(picked).toEqual(["real", "mock"]);
  });

  it("before the server answers both buttons are disabled", () => {
    render(<ModeToggle info={null} onSelect={() => {}} />);
    expect(screen.getByTestId("mode-mock")).toBeDisabled();
    expect(screen.getByTestId("mode-real")).toBeDisabled();
  });

  it("the page loads /api/info into the header toggle and asks for the switch through /api/mode", async () => {
    const calls = stubFetch({
      "GET /api/health": HEALTH, "GET /api/meta": META,
      "GET /api/info": { mode: "local", hosted: false, source: "real", realAvailable: true },
      "POST /api/mode": (b) => ({ mode: "local", hosted: false, source: b.source, realAvailable: true }),
    });
    render(<App />);
    await waitFor(() => expect(screen.getByTestId("mode-real")).toHaveAttribute("aria-pressed", "true"));
    await userEvent.click(screen.getByTestId("mode-mock"));
    await waitFor(() => expect(screen.getByTestId("mode-mock")).toHaveAttribute("aria-pressed", "true"));
    expect(JSON.parse(calls.find((c) => c.path === "/api/mode").init.body)).toEqual({ source: "mock" });
    expect(screen.getByTestId("live")).toHaveTextContent("Mode: Mock.");
  });
});
