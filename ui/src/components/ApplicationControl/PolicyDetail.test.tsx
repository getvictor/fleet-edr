import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import { PolicyDetail } from "./PolicyDetail";
import * as api from "../../api";
import type { ApplicationControlPolicy, ApplicationControlRule } from "../../types";

const makeRule = (over: Partial<ApplicationControlRule> = {}): ApplicationControlRule => ({
  id: 1,
  policy_id: 1,
  rule_type: "BINARY",
  identifier: "a".repeat(64),
  action: "BLOCK",
  enforcement: "PROTECT",
  enabled: true,
  severity: "high",
  source: "admin",
  custom_msg: "Blocked by corp policy",
  created_at: "2026-05-14T00:00:00Z",
  updated_at: "2026-05-14T00:00:00Z",
  created_by: "user:1",
  ...over,
});

const makePolicy = (over: Partial<ApplicationControlPolicy> = {}): ApplicationControlPolicy => ({
  id: 7,
  tenant_id: "default",
  name: "Default",
  description: "Default app-control policy fixture",
  version: 5,
  default_action: "NONE",
  created_at: "2026-05-14T00:00:00Z",
  updated_at: "2026-05-14T00:00:00Z",
  created_by: "system",
  updated_by: "user:1",
  ...over,
});

// PolicyDetail uses useParams, so we route through MemoryRouter +
// Routes so the :id parameter is bound. Wrapping the rendered
// component this way keeps the test focused on the page output
// rather than reproducing the App.tsx routing pyramid.
function renderPolicyDetailAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/app-control/policies/:id" element={<PolicyDetail />} />
      </Routes>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  // Same jsdom-stub posture as AddRuleModal.test.tsx; the runtime
  // existence check trips no-unnecessary-condition because TS
  // believes the prototype methods exist.
  HTMLDialogElement.prototype.showModal = function showModal() {
    this.open = true;
  };
  HTMLDialogElement.prototype.close = function close() {
    this.open = false;
  };
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("PolicyDetail", () => {
  it("renders the policy header + a rules table including the truncated identifier", async () => {
    vi.spyOn(api, "getAppControlPolicy").mockResolvedValue(
      makePolicy({ rules: [makeRule()] }),
    );
    renderPolicyDetailAt("/app-control/policies/7");
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "Default" })).toBeInTheDocument();
    });
    expect(screen.getByText(/version 5/i)).toBeInTheDocument();
    expect(screen.getByText(/default app-control policy fixture/i)).toBeInTheDocument();
    // Identifier is truncated to 16 chars + ellipsis in the table.
    expect(screen.getByText("aaaaaaaaaaaaaaaa…")).toBeInTheDocument();
    expect(screen.getByText(/blocked by corp policy/i)).toBeInTheDocument();
    // Per-row Edit/Disable/Delete render disabled with the coming-soon tooltip.
    const edit = screen.getByRole("button", { name: "Edit" });
    expect(edit).toBeDisabled();
  });

  it("renders an empty-state CTA when the policy has zero rules", async () => {
    vi.spyOn(api, "getAppControlPolicy").mockResolvedValue(
      makePolicy({ rules: [] }),
    );
    renderPolicyDetailAt("/app-control/policies/7");
    await waitFor(() => {
      expect(screen.getByText(/no rules yet/i)).toBeInTheDocument();
    });
    // Add rule button is the primary CTA; renders enabled once
    // policy load completes.
    const addRule = screen.getByRole("button", { name: /add rule/i });
    expect(addRule).not.toBeDisabled();
  });

  it("shows the bad-id message when the URL parameter is not a number", () => {
    renderPolicyDetailAt("/app-control/policies/not-a-number");
    expect(screen.getByText(/invalid policy id/i)).toBeInTheDocument();
  });

  it("surfaces an error when getAppControlPolicy rejects", async () => {
    vi.spyOn(api, "getAppControlPolicy").mockRejectedValue(new Error("nope"));
    renderPolicyDetailAt("/app-control/policies/7");
    await waitFor(() => {
      expect(screen.getByText(/error: nope/i)).toBeInTheDocument();
    });
  });
});
