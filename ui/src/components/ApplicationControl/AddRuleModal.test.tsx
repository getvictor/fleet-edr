import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { AddRuleModal } from "./AddRuleModal";
import * as api from "../../api";
import type { ApplicationControlRule } from "../../types";

// AddRuleModal is the demo cut's only complex form. The tests below
// pin the validation contract the camera-facing flow depends on:
//   - reason is required (gates Save)
//   - BINARY identifier must be 64 lowercase hex chars
//   - More info URL is rejected if it isn't http/https
//   - typed AppControlApiError codes map to readable copy
//   - happy path calls onCreated exactly once
// Native <dialog>'s showModal() isn't implemented in jsdom; the tests
// stub it minimally so the rest of the React tree renders.

const makeRule = (over: Partial<ApplicationControlRule> = {}): ApplicationControlRule => ({
  id: 1,
  policy_id: 1,
  rule_type: "BINARY",
  identifier: "a".repeat(64),
  action: "BLOCK",
  enforcement: "PROTECT",
  enabled: true,
  severity: "medium",
  source: "admin",
  created_at: "2026-05-14T00:00:00Z",
  updated_at: "2026-05-14T00:00:00Z",
  created_by: "user:1",
  ...over,
});

// jsdom doesn't implement HTMLDialogElement.showModal/close; patch
// them as no-ops on the prototype so the modal renders without
// throwing TypeError.
beforeEach(() => {
  // jsdom doesn't implement HTMLDialogElement.showModal/close.
  // The TS prototype claims both exist, so the runtime existence
  // check tripping no-unnecessary-condition is expected; assign
  // unconditionally instead.
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

describe("AddRuleModal", () => {
  it("does not render content when closed", () => {
    render(
      <AddRuleModal
        open={false}
        policyID={1}
        onClose={() => undefined}
        onCreated={() => undefined}
      />,
    );
    // Title only shows once the dialog is open; we can't assert
    // it's gone (it's still in the DOM under jsdom's stubbed
    // showModal) but the dialog element should not have its
    // `open` attribute set.
    const dialog = document.querySelector("dialog");
    expect(dialog).not.toBeNull();
    expect((dialog as HTMLDialogElement).open).toBe(false);
  });

  it("disables Save until both identifier and reason are populated", () => {
    render(
      <AddRuleModal
        open
        policyID={1}
        onClose={() => undefined}
        onCreated={() => undefined}
      />,
    );
    const save = screen.getByRole("button", { name: /save rule/i });
    expect(save).toBeDisabled();
    fireEvent.change(screen.getByLabelText(/identifier/i), {
      target: { value: "a".repeat(64) },
    });
    expect(save).toBeDisabled();
    fireEvent.change(screen.getByLabelText(/reason/i), {
      target: { value: "demo" },
    });
    expect(save).not.toBeDisabled();
  });

  it("rejects an identifier that is not 64 lowercase hex characters", async () => {
    const createSpy = vi.spyOn(api, "createAppControlRule");
    render(
      <AddRuleModal
        open
        policyID={1}
        onClose={() => undefined}
        onCreated={() => undefined}
      />,
    );
    fireEvent.change(screen.getByLabelText(/identifier/i), {
      target: { value: "not-a-real-hash" },
    });
    fireEvent.change(screen.getByLabelText(/reason/i), {
      target: { value: "demo" },
    });
    fireEvent.click(screen.getByRole("button", { name: /save rule/i }));
    await waitFor(() => {
      expect(screen.getByRole("alert").textContent).toMatch(/BINARY identifier/i);
    });
    expect(createSpy).not.toHaveBeenCalled();
  });

  it("rejects a BINARY identifier with the wrong length", async () => {
    const createSpy = vi.spyOn(api, "createAppControlRule");
    render(
      <AddRuleModal
        open
        policyID={1}
        onClose={() => undefined}
        onCreated={() => undefined}
      />,
    );
    // 40 hex chars is the CDHASH length, not the BINARY length (64). The validator
    // should reject it on the length check, before the charset regex runs. We pick
    // this shape because uppercase hex now intentionally passes (the validator
    // lowercases via trim().toLowerCase() and the submit path normalises), so the
    // distinct exercise is the length gate.
    fireEvent.change(screen.getByLabelText(/identifier/i), {
      target: { value: "a".repeat(40) },
    });
    fireEvent.change(screen.getByLabelText(/reason/i), {
      target: { value: "demo" },
    });
    fireEvent.click(screen.getByRole("button", { name: /save rule/i }));
    await waitFor(() => {
      expect(screen.getByRole("alert").textContent).toMatch(/64 hex characters/i);
    });
    expect(createSpy).not.toHaveBeenCalled();
  });

  it("accepts BINARY hex with uppercase letters (lowercased before submit)", async () => {
    const createSpy = vi.spyOn(api, "createAppControlRule").mockResolvedValue({
      id: 99,
      policy_id: 1,
      rule_type: "BINARY",
      identifier: "a".repeat(64),
      action: "BLOCK",
      enforcement: "PROTECT",
      enabled: true,
      severity: "medium",
      source: "admin",
      created_at: "2026-05-17T00:00:00Z",
      updated_at: "2026-05-17T00:00:00Z",
      created_by: "operator",
    });
    render(
      <AddRuleModal
        open
        policyID={1}
        onClose={() => undefined}
        onCreated={() => undefined}
      />,
    );
    fireEvent.change(screen.getByLabelText(/identifier/i), {
      target: { value: "A".repeat(64) },
    });
    fireEvent.change(screen.getByLabelText(/reason/i), {
      target: { value: "uppercase normalisation" },
    });
    fireEvent.click(screen.getByRole("button", { name: /save rule/i }));
    await waitFor(() => {
      expect(createSpy).toHaveBeenCalled();
    });
    // The submit body must carry the lowercased identifier even though the operator typed uppercase.
    const submitted = createSpy.mock.calls[0][1] as { identifier: string };
    expect(submitted.identifier).toBe("a".repeat(64));
  });

  it("rejects a non-http(s) More info URL", async () => {
    const createSpy = vi.spyOn(api, "createAppControlRule");
    render(
      <AddRuleModal
        open
        policyID={1}
        onClose={() => undefined}
        onCreated={() => undefined}
      />,
    );
    fireEvent.change(screen.getByLabelText(/identifier/i), {
      target: { value: "a".repeat(64) },
    });
    fireEvent.change(screen.getByLabelText(/reason/i), {
      target: { value: "demo" },
    });
    fireEvent.change(screen.getByLabelText(/more info url/i), {
      target: { value: "javascript:alert(1)" },
    });
    fireEvent.click(screen.getByRole("button", { name: /save rule/i }));
    await waitFor(() => {
      expect(screen.getByRole("alert").textContent).toMatch(/http or https/i);
    });
    expect(createSpy).not.toHaveBeenCalled();
  });

  it("submits and fires onCreated on the happy path", async () => {
    const created = makeRule();
    const createSpy = vi
      .spyOn(api, "createAppControlRule")
      .mockResolvedValue(created);
    const onCreated = vi.fn();
    render(
      <AddRuleModal
        open
        policyID={42}
        onClose={() => undefined}
        onCreated={onCreated}
      />,
    );
    fireEvent.change(screen.getByLabelText(/identifier/i), {
      target: { value: "b".repeat(64) },
    });
    fireEvent.change(screen.getByLabelText(/reason/i), {
      target: { value: "demo rehearsal" },
    });
    fireEvent.change(screen.getByLabelText(/custom message/i), {
      target: { value: "Blocked by corp policy" },
    });
    fireEvent.click(screen.getByRole("button", { name: /save rule/i }));
    await waitFor(() => {
      expect(createSpy).toHaveBeenCalledTimes(1);
    });
    expect(createSpy).toHaveBeenCalledWith(42, expect.objectContaining({
      rule_type: "BINARY",
      identifier: "b".repeat(64),
      reason: "demo rehearsal",
      severity: "medium",
      custom_msg: "Blocked by corp policy",
    }));
    await waitFor(() => {
      expect(onCreated).toHaveBeenCalledTimes(1);
    });
  });

  it("maps a duplicate_rule AppControlApiError to a readable message", async () => {
    vi.spyOn(api, "createAppControlRule").mockRejectedValue(
      new api.AppControlApiError("application_control.duplicate_rule", "duplicate", 409),
    );
    render(
      <AddRuleModal
        open
        policyID={1}
        onClose={() => undefined}
        onCreated={() => undefined}
      />,
    );
    fireEvent.change(screen.getByLabelText(/identifier/i), {
      target: { value: "c".repeat(64) },
    });
    fireEvent.change(screen.getByLabelText(/reason/i), {
      target: { value: "demo" },
    });
    fireEvent.click(screen.getByRole("button", { name: /save rule/i }));
    await waitFor(() => {
      expect(screen.getByRole("alert").textContent).toMatch(/already exists/i);
    });
  });

  it("falls back to the server's message for an unknown error code", async () => {
    vi.spyOn(api, "createAppControlRule").mockRejectedValue(
      new api.AppControlApiError("application_control.unmapped", "server message", 400),
    );
    render(
      <AddRuleModal
        open
        policyID={1}
        onClose={() => undefined}
        onCreated={() => undefined}
      />,
    );
    fireEvent.change(screen.getByLabelText(/identifier/i), {
      target: { value: "d".repeat(64) },
    });
    fireEvent.change(screen.getByLabelText(/reason/i), {
      target: { value: "demo" },
    });
    fireEvent.click(screen.getByRole("button", { name: /save rule/i }));
    await waitFor(() => {
      expect(screen.getByRole("alert").textContent).toMatch(/server message/i);
    });
  });

  it("invokes onClose when the Cancel button is clicked", () => {
    const onClose = vi.fn();
    render(
      <AddRuleModal
        open
        policyID={1}
        onClose={onClose}
        onCreated={() => undefined}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: /cancel/i }));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("accepts a valid TEAMID identifier and submits with rule_type=TEAMID", async () => {
    const createSpy = vi
      .spyOn(api, "createAppControlRule")
      .mockResolvedValue(makeRule({ rule_type: "TEAMID", identifier: "EQHXZ8M8AV" }));
    render(
      <AddRuleModal open policyID={1} onClose={() => undefined} onCreated={() => undefined} />,
    );
    fireEvent.change(screen.getByLabelText(/^type$/i), { target: { value: "TEAMID" } });
    fireEvent.change(screen.getByLabelText(/identifier/i), { target: { value: "EQHXZ8M8AV" } });
    fireEvent.change(screen.getByLabelText(/reason/i), { target: { value: "block this team" } });
    fireEvent.click(screen.getByRole("button", { name: /save rule/i }));
    await waitFor(() => {
      expect(createSpy).toHaveBeenCalledWith(1, expect.objectContaining({
        rule_type: "TEAMID",
        identifier: "EQHXZ8M8AV",
      }));
    });
  });

  it("rejects a lowercase TEAMID identifier with a specific error", async () => {
    const createSpy = vi.spyOn(api, "createAppControlRule");
    render(
      <AddRuleModal open policyID={1} onClose={() => undefined} onCreated={() => undefined} />,
    );
    fireEvent.change(screen.getByLabelText(/^type$/i), { target: { value: "TEAMID" } });
    fireEvent.change(screen.getByLabelText(/identifier/i), { target: { value: "eqhxz8m8av" } });
    fireEvent.change(screen.getByLabelText(/reason/i), { target: { value: "demo" } });
    fireEvent.click(screen.getByRole("button", { name: /save rule/i }));
    await waitFor(() => {
      expect(screen.getByRole("alert").textContent).toMatch(/TEAMID must be 10 uppercase/i);
    });
    expect(createSpy).not.toHaveBeenCalled();
  });

  it("accepts a valid CDHASH identifier and submits with rule_type=CDHASH", async () => {
    const createSpy = vi
      .spyOn(api, "createAppControlRule")
      .mockResolvedValue(makeRule({ rule_type: "CDHASH", identifier: "c".repeat(40) }));
    render(
      <AddRuleModal open policyID={1} onClose={() => undefined} onCreated={() => undefined} />,
    );
    fireEvent.change(screen.getByLabelText(/^type$/i), { target: { value: "CDHASH" } });
    fireEvent.change(screen.getByLabelText(/identifier/i), { target: { value: "C".repeat(40) } });
    fireEvent.change(screen.getByLabelText(/reason/i), { target: { value: "block this CDHash" } });
    fireEvent.click(screen.getByRole("button", { name: /save rule/i }));
    await waitFor(() => {
      // CDHASH identifiers normalize to lowercase before submission.
      expect(createSpy).toHaveBeenCalledWith(1, expect.objectContaining({
        rule_type: "CDHASH",
        identifier: "c".repeat(40),
      }));
    });
  });

  it("accepts a valid SIGNINGID identifier in TeamID:bundle.id form", async () => {
    const createSpy = vi
      .spyOn(api, "createAppControlRule")
      .mockResolvedValue(makeRule({ rule_type: "SIGNINGID", identifier: "EQHXZ8M8AV:com.google.Chrome" }));
    render(
      <AddRuleModal open policyID={1} onClose={() => undefined} onCreated={() => undefined} />,
    );
    fireEvent.change(screen.getByLabelText(/^type$/i), { target: { value: "SIGNINGID" } });
    fireEvent.change(screen.getByLabelText(/identifier/i), {
      target: { value: "EQHXZ8M8AV:com.google.Chrome" },
    });
    fireEvent.change(screen.getByLabelText(/reason/i), { target: { value: "block chrome" } });
    fireEvent.click(screen.getByRole("button", { name: /save rule/i }));
    await waitFor(() => {
      expect(createSpy).toHaveBeenCalledWith(1, expect.objectContaining({
        rule_type: "SIGNINGID",
        identifier: "EQHXZ8M8AV:com.google.Chrome",
      }));
    });
  });

  it("accepts a SIGNINGID identifier with the platform: prefix", async () => {
    const createSpy = vi
      .spyOn(api, "createAppControlRule")
      .mockResolvedValue(makeRule({ rule_type: "SIGNINGID", identifier: "platform:com.apple.curl" }));
    render(
      <AddRuleModal open policyID={1} onClose={() => undefined} onCreated={() => undefined} />,
    );
    fireEvent.change(screen.getByLabelText(/^type$/i), { target: { value: "SIGNINGID" } });
    fireEvent.change(screen.getByLabelText(/identifier/i), {
      target: { value: "platform:com.apple.curl" },
    });
    fireEvent.change(screen.getByLabelText(/reason/i), { target: { value: "block platform curl" } });
    fireEvent.click(screen.getByRole("button", { name: /save rule/i }));
    await waitFor(() => {
      expect(createSpy).toHaveBeenCalledWith(1, expect.objectContaining({
        rule_type: "SIGNINGID",
        identifier: "platform:com.apple.curl",
      }));
    });
  });

  it("rejects a malformed SIGNINGID missing the colon", async () => {
    const createSpy = vi.spyOn(api, "createAppControlRule");
    render(
      <AddRuleModal open policyID={1} onClose={() => undefined} onCreated={() => undefined} />,
    );
    fireEvent.change(screen.getByLabelText(/^type$/i), { target: { value: "SIGNINGID" } });
    fireEvent.change(screen.getByLabelText(/identifier/i), {
      target: { value: "EQHXZ8M8AVcom.google.Chrome" },
    });
    fireEvent.change(screen.getByLabelText(/reason/i), { target: { value: "demo" } });
    fireEvent.click(screen.getByRole("button", { name: /save rule/i }));
    await waitFor(() => {
      expect(screen.getByRole("alert").textContent).toMatch(/SIGNINGID must look like/i);
    });
    expect(createSpy).not.toHaveBeenCalled();
  });

  // CERTIFICATE + PATH shipped end to end in PR #210 (server validation + extension AUTH_EXEC enforcement); these pin that the UI
  // exposes them as authorable rule types rather than the "(coming soon)" disabled options they used to render as.
  it("offers CERTIFICATE and PATH as selectable (not disabled) rule types", () => {
    render(
      <AddRuleModal open policyID={1} onClose={() => undefined} onCreated={() => undefined} />,
    );
    const cert = screen.getByRole<HTMLOptionElement>("option", { name: /CERTIFICATE/i });
    const path = screen.getByRole<HTMLOptionElement>("option", { name: /PATH/i });
    expect(cert.disabled).toBe(false);
    expect(path.disabled).toBe(false);
    expect(cert.textContent).not.toMatch(/coming soon/i);
    expect(path.textContent).not.toMatch(/coming soon/i);
  });

  it("accepts a valid CERTIFICATE identifier and submits it lowercased with rule_type=CERTIFICATE", async () => {
    const createSpy = vi
      .spyOn(api, "createAppControlRule")
      .mockResolvedValue(makeRule({ rule_type: "CERTIFICATE", identifier: "d".repeat(64) }));
    render(
      <AddRuleModal open policyID={1} onClose={() => undefined} onCreated={() => undefined} />,
    );
    fireEvent.change(screen.getByLabelText(/^type$/i), { target: { value: "CERTIFICATE" } });
    fireEvent.change(screen.getByLabelText(/identifier/i), { target: { value: "D".repeat(64) } });
    fireEvent.change(screen.getByLabelText(/reason/i), { target: { value: "revoked leaf cert" } });
    fireEvent.click(screen.getByRole("button", { name: /save rule/i }));
    await waitFor(() => {
      // CERTIFICATE shares BINARY's 64-hex shape and normalizes to lowercase before submission.
      expect(createSpy).toHaveBeenCalledWith(1, expect.objectContaining({
        rule_type: "CERTIFICATE",
        identifier: "d".repeat(64),
      }));
    });
  });

  it("rejects a CERTIFICATE identifier that is not 64 hex characters", async () => {
    const createSpy = vi.spyOn(api, "createAppControlRule");
    render(
      <AddRuleModal open policyID={1} onClose={() => undefined} onCreated={() => undefined} />,
    );
    fireEvent.change(screen.getByLabelText(/^type$/i), { target: { value: "CERTIFICATE" } });
    fireEvent.change(screen.getByLabelText(/identifier/i), { target: { value: "abc123" } });
    fireEvent.change(screen.getByLabelText(/reason/i), { target: { value: "demo" } });
    fireEvent.click(screen.getByRole("button", { name: /save rule/i }));
    await waitFor(() => {
      expect(screen.getByRole("alert").textContent).toMatch(/CERTIFICATE identifier must be 64 hex/i);
    });
    expect(createSpy).not.toHaveBeenCalled();
  });

  it("accepts an absolute PATH and submits it verbatim with rule_type=PATH (server canonicalizes)", async () => {
    const createSpy = vi
      .spyOn(api, "createAppControlRule")
      .mockResolvedValue(makeRule({ rule_type: "PATH", identifier: "/private/tmp/dropper" }));
    render(
      <AddRuleModal open policyID={1} onClose={() => undefined} onCreated={() => undefined} />,
    );
    fireEvent.change(screen.getByLabelText(/^type$/i), { target: { value: "PATH" } });
    // The client sends the operator's literal absolute path; the server's NormalizeIdentifier canonicalizes /tmp -> /private/tmp.
    fireEvent.change(screen.getByLabelText(/identifier/i), { target: { value: "/tmp/dropper" } });
    fireEvent.change(screen.getByLabelText(/reason/i), { target: { value: "block dropper path" } });
    fireEvent.click(screen.getByRole("button", { name: /save rule/i }));
    await waitFor(() => {
      expect(createSpy).toHaveBeenCalledWith(1, expect.objectContaining({
        rule_type: "PATH",
        identifier: "/tmp/dropper",
      }));
    });
  });

  it("rejects a relative PATH", async () => {
    const createSpy = vi.spyOn(api, "createAppControlRule");
    render(
      <AddRuleModal open policyID={1} onClose={() => undefined} onCreated={() => undefined} />,
    );
    fireEvent.change(screen.getByLabelText(/^type$/i), { target: { value: "PATH" } });
    fireEvent.change(screen.getByLabelText(/identifier/i), { target: { value: "usr/local/bin/foo" } });
    fireEvent.change(screen.getByLabelText(/reason/i), { target: { value: "demo" } });
    fireEvent.click(screen.getByRole("button", { name: /save rule/i }));
    await waitFor(() => {
      expect(screen.getByRole("alert").textContent).toMatch(/PATH must be an absolute path/i);
    });
    expect(createSpy).not.toHaveBeenCalled();
  });

  it("rejects a PATH containing `..` segments", async () => {
    const createSpy = vi.spyOn(api, "createAppControlRule");
    render(
      <AddRuleModal open policyID={1} onClose={() => undefined} onCreated={() => undefined} />,
    );
    fireEvent.change(screen.getByLabelText(/^type$/i), { target: { value: "PATH" } });
    fireEvent.change(screen.getByLabelText(/identifier/i), { target: { value: "/var/foo/../../etc/sudoers" } });
    fireEvent.change(screen.getByLabelText(/reason/i), { target: { value: "demo" } });
    fireEvent.click(screen.getByRole("button", { name: /save rule/i }));
    await waitFor(() => {
      expect(screen.getByRole("alert").textContent).toMatch(/must not contain `\.\.`/i);
    });
    expect(createSpy).not.toHaveBeenCalled();
  });
});
