import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { PoliciesList } from "./PoliciesList";
import * as api from "../../api";
import type { ApplicationControlPolicy, ApplicationControlRule } from "../../types";

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
  // Default fixture mirrors the Phase A seed: Default policy assigned to all-hosts is exactly 1 assignment.
  assignment_count: 1,
  ...over,
});

const makeRule = (over: Partial<ApplicationControlRule> = {}): ApplicationControlRule => ({
  id: 1,
  policy_id: 1,
  rule_type: "BINARY",
  identifier: "abc123",
  action: "BLOCK",
  enforcement: "ENFORCED",
  enabled: true,
  severity: "medium",
  source: "manual",
  created_at: "2026-05-14T00:00:00Z",
  updated_at: "2026-05-14T00:00:00Z",
  created_by: "system",
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
    // The "Rules" column should render the dash placeholder.
    expect(screen.getByText("-")).toBeInTheDocument();
  });

  it("renders the rule count when the policy carries a rules array", async () => {
    vi.mocked(api.listAppControlPolicies).mockResolvedValue([
      makePolicy({ name: "WithRules", rules: [makeRule({ id: 1 }), makeRule({ id: 2 })] }),
    ]);
    render(
      <MemoryRouter>
        <PoliciesList />
      </MemoryRouter>,
    );
    await waitFor(() => {
      expect(screen.getByText("WithRules")).toBeInTheDocument();
    });
    // rules present, so ruleCount renders the length rather than the "-" placeholder.
    expect(screen.getByText("2")).toBeInTheDocument();
  });

  it("renders assignment_count with the appropriate singular / plural / zero label", async () => {
    (api.listAppControlPolicies as unknown as ReturnType<typeof vi.fn>).mockResolvedValue([
      makePolicy({ id: 1, name: "SeedDefault", assignment_count: 1 }),
      makePolicy({ id: 2, name: "MultiAssigned", assignment_count: 3 }),
      makePolicy({ id: 3, name: "Unwired", assignment_count: 0 }),
    ]);
    render(
      <MemoryRouter>
        <PoliciesList />
      </MemoryRouter>,
    );
    await waitFor(() => {
      expect(screen.getByText("SeedDefault")).toBeInTheDocument();
    });
    // The Phase A "always 1" seed case renders as "1 host group". The plural form switches at 2+; the zero state renders
    // "no host groups" (an admin posture, not a wire-shape error). The previous hardcoded "all hosts" placeholder must
    // not appear anywhere -- if it does, the wiring regressed back to the demo-cut shape.
    expect(screen.getByText("1 host group")).toBeInTheDocument();
    expect(screen.getByText("3 host groups")).toBeInTheDocument();
    expect(screen.getByText("no host groups")).toBeInTheDocument();
    expect(screen.queryByText(/^all hosts$/)).not.toBeInTheDocument();
  });
});
