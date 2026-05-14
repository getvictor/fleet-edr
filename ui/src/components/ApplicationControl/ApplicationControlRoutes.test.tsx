import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import { ApplicationControlRoutes } from "./ApplicationControlRoutes";
import * as api from "../../api";

// Shallow-render the feature router under several entry paths and
// confirm the right page mounts. Mocks the api so the rendered
// children stay deterministic; we're testing the route table here,
// not the page contents.
afterEach(() => {
  vi.restoreAllMocks();
});

describe("ApplicationControlRoutes", () => {
  it("renders PoliciesList at the index route", async () => {
    vi.spyOn(api, "listAppControlPolicies").mockResolvedValue([]);
    render(
      <MemoryRouter initialEntries={["/app-control"]}>
        <Routes>
          <Route path="/app-control/*" element={<ApplicationControlRoutes />} />
        </Routes>
      </MemoryRouter>,
    );
    await waitFor(() => {
      // PageHeader title "Application control" is unique to the
      // PoliciesList page in this surface.
      expect(screen.getByRole("heading", { name: /application control/i })).toBeInTheDocument();
    });
  });

  it("falls back to the policies list on an unknown subpath", async () => {
    vi.spyOn(api, "listAppControlPolicies").mockResolvedValue([]);
    render(
      <MemoryRouter initialEntries={["/app-control/garbage"]}>
        <Routes>
          <Route path="/app-control/*" element={<ApplicationControlRoutes />} />
        </Routes>
      </MemoryRouter>,
    );
    await waitFor(() => {
      // After the Navigate fires, the index PoliciesList page mounts.
      expect(screen.getByText(/no policies found/i)).toBeInTheDocument();
    });
  });
});
