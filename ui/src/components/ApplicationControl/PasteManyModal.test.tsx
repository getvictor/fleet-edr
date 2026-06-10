import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { PasteManyModal } from "./PasteManyModal";
import * as api from "../../api";
import type { BulkUpsertAppControlResult } from "../../api";

// PasteManyModal pins the two-phase paste flow: paste -> preview with per-row override -> bulk-upsert submit. Tests focus on
// the behaviors that distinguish it from AddRuleModal: parse routing, per-row override, unresolved-type guard, and the typed
// API error path.

const fakeResult: BulkUpsertAppControlResult = { inserted: 2, updated: 0, rules: [] };

beforeEach(() => {
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

describe("PasteManyModal", () => {
  it("does not surface the preview content until Parse runs", () => {
    render(
      <PasteManyModal open policyID={1} onClose={() => undefined} onUpserted={() => undefined} />,
    );
    expect(screen.queryByRole("table")).toBeNull();
    expect(screen.getByRole("button", { name: /parse/i })).toBeDisabled();
  });

  it("parses the textarea into the preview table on Parse and infers types per the spec", () => {
    render(
      <PasteManyModal open policyID={1} onClose={() => undefined} onUpserted={() => undefined} />,
    );
    const textarea = screen.getByLabelText(/identifiers/i);
    const input = [
      "a".repeat(40),
      "b".repeat(64),
      "EQHXZ8M8AV",
      "platform:com.apple.curl",
    ].join("\n");
    fireEvent.change(textarea, { target: { value: input } });
    fireEvent.click(screen.getByRole("button", { name: /parse/i }));
    expect(screen.getByRole("table")).toBeTruthy();
    const selects = screen.getAllByRole("combobox", { name: /^type for row/i });
    expect(selects).toHaveLength(4);
    expect((selects[0] as HTMLSelectElement).value).toBe("CDHASH");
    expect((selects[1] as HTMLSelectElement).value).toBe("BINARY");
    expect((selects[2] as HTMLSelectElement).value).toBe("TEAMID");
    expect((selects[3] as HTMLSelectElement).value).toBe("SIGNINGID");
  });

  it("disables Save when any row's type is unresolved (no shape matched)", () => {
    render(
      <PasteManyModal open policyID={1} onClose={() => undefined} onUpserted={() => undefined} />,
    );
    fireEvent.change(screen.getByLabelText(/identifiers/i), {
      target: { value: "wat is this even\n" + "a".repeat(64) },
    });
    fireEvent.click(screen.getByRole("button", { name: /parse/i }));
    fireEvent.change(screen.getByLabelText(/reason/i), { target: { value: "import" } });
    expect(screen.getByRole("button", { name: /save 2 rules/i })).toBeDisabled();
  });

  it("disables Save when an inferred type is unavailable (CERTIFICATE/PATH) until overridden", () => {
    render(
      <PasteManyModal open policyID={1} onClose={() => undefined} onUpserted={() => undefined} />,
    );
    // PATH is inferred but unavailable; the row's type must be switched to a supported type before Save unlocks.
    fireEvent.change(screen.getByLabelText(/identifiers/i), {
      target: { value: "/Applications/Mail.app/Contents/MacOS/Mail" },
    });
    fireEvent.click(screen.getByRole("button", { name: /parse/i }));
    fireEvent.change(screen.getByLabelText(/reason/i), { target: { value: "import" } });
    const save = screen.getByRole("button", { name: /save 1 rule/i });
    expect(save).toBeDisabled();

    // Override to BINARY (still wrong shape but the modal is advisory: server will reject; pre-submit gate is satisfied).
    const select = screen.getByRole("combobox", { name: /^type for row 1/i });
    fireEvent.change(select, { target: { value: "BINARY" } });
    expect(save).not.toBeDisabled();
  });

  it("submits the bulk-upsert request and fires onUpserted on success", async () => {
    const bulkSpy = vi.spyOn(api, "bulkUpsertAppControlRules").mockResolvedValue(fakeResult);
    const onUpserted = vi.fn();
    render(
      <PasteManyModal open policyID={7} onClose={() => undefined} onUpserted={onUpserted} />,
    );
    fireEvent.change(screen.getByLabelText(/identifiers/i), {
      target: { value: "a".repeat(64) + "\nb".repeat(0) + "\nEQHXZ8M8AV" },
    });
    fireEvent.click(screen.getByRole("button", { name: /parse/i }));
    fireEvent.change(screen.getByLabelText(/reason/i), { target: { value: "import" } });
    fireEvent.click(screen.getByRole("button", { name: /save 2 rules/i }));

    await waitFor(() => {
      expect(bulkSpy).toHaveBeenCalledTimes(1);
      expect(onUpserted).toHaveBeenCalledWith(fakeResult);
    });
    expect(bulkSpy).toHaveBeenCalledWith(7, {
      rules: [
        { rule_type: "BINARY", identifier: "a".repeat(64), severity: "medium" },
        { rule_type: "TEAMID", identifier: "EQHXZ8M8AV", severity: "medium" },
      ],
      reason: "import",
    });
  });

  it("surfaces a typed AppControlApiError message inline without firing onUpserted", async () => {
    // For invalid_rule, the modal intentionally falls through to the server's per-item message (e.g. "bulk item 1: ...")
    // rather than overriding with generic copy: the row index is strictly more useful to the operator than any UI string.
    vi.spyOn(api, "bulkUpsertAppControlRules").mockRejectedValue(
      new api.AppControlApiError(
        "application_control.invalid_rule",
        "bulk item 1: identifier failed validation",
        400,
      ),
    );
    const onUpserted = vi.fn();
    render(
      <PasteManyModal open policyID={1} onClose={() => undefined} onUpserted={onUpserted} />,
    );
    fireEvent.change(screen.getByLabelText(/identifiers/i), { target: { value: "a".repeat(64) } });
    fireEvent.click(screen.getByRole("button", { name: /parse/i }));
    fireEvent.change(screen.getByLabelText(/reason/i), { target: { value: "import" } });
    fireEvent.click(screen.getByRole("button", { name: /save 1 rule/i }));
    await waitFor(() => {
      expect(screen.getByRole("alert").textContent).toMatch(/bulk item 1: identifier failed validation/);
    });
    expect(onUpserted).not.toHaveBeenCalled();
  });

  it("Back button returns to the paste phase and clears rows", () => {
    render(
      <PasteManyModal open policyID={1} onClose={() => undefined} onUpserted={() => undefined} />,
    );
    fireEvent.change(screen.getByLabelText(/identifiers/i), {
      target: { value: "EQHXZ8M8AV" },
    });
    fireEvent.click(screen.getByRole("button", { name: /parse/i }));
    expect(screen.getByRole("table")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /back to paste/i }));
    expect(screen.queryByRole("table")).toBeNull();
    expect(screen.getByLabelText(/identifiers/i)).toBeTruthy();
  });

  it("removes a single row via the per-row × button", () => {
    render(
      <PasteManyModal open policyID={1} onClose={() => undefined} onUpserted={() => undefined} />,
    );
    fireEvent.change(screen.getByLabelText(/identifiers/i), {
      target: { value: ["a".repeat(64), "b".repeat(64)].join("\n") },
    });
    fireEvent.click(screen.getByRole("button", { name: /parse/i }));
    expect(screen.getAllByRole("combobox", { name: /^type for row/i })).toHaveLength(2);
    fireEvent.click(screen.getByRole("button", { name: /remove row 1/i }));
    expect(screen.getAllByRole("combobox", { name: /^type for row/i })).toHaveLength(1);
  });
});
