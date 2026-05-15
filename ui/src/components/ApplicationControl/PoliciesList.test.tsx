import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { PoliciesList } from "./PoliciesList";
import * as api from "../../api";
import type { ApplicationControlPolicy } from "../../types";

const makePolicy = (over: Partial<ApplicationControlPolicy> = {}): ApplicationControlPolicy => ({
  id: 1,
  name: "Default",
  description: "",
  version: 3,
  default_action: "NONE",
  created_at: "2026-05-14T00:00:00Z",
  updated_at: "2026-05-14T00:00:00Z",
  created_by: "system",
  updated_by: "user:1",
  ...over,
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("PoliciesList", () => {
  beforeEach(() => {
    vi.spyOn(api, "listAppControlPolicies");
  });

  it("renders a loading state, then the seeded Default policy row", async () => {
    (api.listAppControlPolicies as unknown as ReturnType<typeof vi.fn>).mockResolvedValue([
      makePolicy({ description: "Default app-control policy fixture" }),
    ]);
    render(
      <MemoryRouter>
        <PoliciesList />
      </MemoryRouter>,
    );
    expect(screen.getByText(/loading policies/i)).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.getByText("Default")).toBeInTheDocument();
    });
    expect(screen.getByText(/default app-control policy fixture/i)).toBeInTheDocument();
    // The "New policy" button renders disabled with the coming-soon
    // tooltip per the demo plan's section F.
    const newPolicy = screen.getByRole("button", { name: /new policy/i });
    expect(newPolicy).toBeDisabled();
    expect(newPolicy).toHaveAttribute("title", expect.stringMatching(/coming/i));
  });

  it("renders an empty state when there are no policies yet", async () => {
    (api.listAppControlPolicies as unknown as ReturnType<typeof vi.fn>).mockResolvedValue([]);
    render(
      <MemoryRouter>
        <PoliciesList />
      </MemoryRouter>,
    );
    await waitFor(() => {
      expect(screen.getByText(/no policies found/i)).toBeInTheDocument();
    });
  });

  it("surfaces the error message when listAppControlPolicies rejects", async () => {
    (api.listAppControlPolicies as unknown as ReturnType<typeof vi.fn>).mockRejectedValue(
      new Error("boom"),
    );
    render(
      <MemoryRouter>
        <PoliciesList />
      </MemoryRouter>,
    );
    await waitFor(() => {
      expect(screen.getByText(/error: boom/i)).toBeInTheDocument();
    });
  });

  it("shows a dash when the rule count isn't available (list endpoint omits it)", async () => {
    (api.listAppControlPolicies as unknown as ReturnType<typeof vi.fn>).mockResolvedValue([
      makePolicy(),
    ]);
    render(
      <MemoryRouter>
        <PoliciesList />
      </MemoryRouter>,
    );
    await waitFor(() => {
      expect(screen.getByText("Default")).toBeInTheDocument();
    });
    // The "Rules" column should render the em dash placeholder.
    expect(screen.getByText("—")).toBeInTheDocument();
  });
});
