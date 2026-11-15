import React from "react";
import { cleanup, render, screen, within } from "@testing-library/react";
import App from "./App.jsx";
import { CASES, COMPARE, HEALTH, META, stubFetch } from "./test/fixtures.js";

// The header shows this lab's own Verified / In progress mark, read from the same /api/shelf call the Shelf link makes (through the lab-proxy that
// call reaches the shelf, whose payload lists every demo with its mark). The lab's own /api/shelf has no demos, so there is no mark then.
const base = { "GET /api/health": HEALTH, "GET /api/meta": META, "GET /api/tester/cases": { cases: CASES }, "GET /api/flows/compare": COMPARE };
const mark = (status, label, extra = {}) => ({ status, label, note: "", updatedAt: "2026-11-15", source: "shipped", ...extra });
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

describe("verification mark in the header", () => {
  it("shows this lab's own mark after the Shelf link, and no other lab's", async () => {
    stubFetch({ ...base, "GET /api/shelf": { shelfUrl: "http://shelf.example", demos: [{ id: "other-lab", verification: mark("in-progress", "In progress") }, { id: "token-workbench", verification: mark("verified", "Verified", { note: "All four tabs run on the mock" }) }] } });
    render(<App />);
    const bar = within(await screen.findByTestId("top-menu"));
    expect(await bar.findByText("Verified")).toBeInTheDocument();
    expect(bar.getByRole("link", { name: /Shelf/ })).toBeInTheDocument();
    expect(bar.queryByText("In progress")).toBeNull();
    expect(bar.getByText("Verified").closest(".verify")).toHaveAttribute("title", expect.stringContaining("All four tabs run on the mock"));
  });

  it("shows nothing when the lab is opened on its own port (its /api/shelf has no demos) or the shelf has no mark for it", async () => {
    for (const shelf of [{ shelfUrl: "http://shelf.example" }, { shelfUrl: "http://shelf.example", demos: [{ id: "token-workbench", verification: null }] }]) {
      stubFetch({ ...base, "GET /api/shelf": shelf });
      const { unmount } = render(<App />);
      const bar = within(await screen.findByTestId("top-menu"));
      expect(await bar.findByRole("link", { name: /Shelf/ })).toBeInTheDocument(); // the shelf answered, and still no badge
      expect(document.querySelector(".verify")).toBeNull();
      unmount();
    }
  });
});
