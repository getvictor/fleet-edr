import { describe, it, expect, vi } from "vitest";
import { applyAppControlSubmitError } from "./dialogErrors";
import { AppControlApiError, ReauthRequiredError } from "../../api";

const KNOWN_CODES = new Map<string, string>([
  ["application_control.rule_not_found", "Rule gone."],
  ["application_control.policy_immutable", "Default policy is immutable."],
]);

describe("applyAppControlSubmitError", () => {
  it("returns true for ReauthRequiredError and does NOT set a form error", () => {
    const setFormError = vi.fn<(msg: string) => void>();
    const result = applyAppControlSubmitError(
      new ReauthRequiredError({ authMethod: "local_password", reauthURL: "/login" }),
      setFormError,
      KNOWN_CODES,
      "fallback",
    );
    expect(result).toBe(true);
    expect(setFormError).not.toHaveBeenCalled();
  });

  it("maps a known AppControlApiError code to the human-readable message", () => {
    const setFormError = vi.fn<(msg: string) => void>();
    const result = applyAppControlSubmitError(
      new AppControlApiError("application_control.rule_not_found", "rule not found", 404),
      setFormError,
      KNOWN_CODES,
      "fallback",
    );
    expect(result).toBe(false);
    expect(setFormError).toHaveBeenCalledWith("Rule gone.");
  });

  it("falls back to the server message when the AppControlApiError code is unknown", () => {
    const setFormError = vi.fn<(msg: string) => void>();
    const result = applyAppControlSubmitError(
      new AppControlApiError("application_control.future_code", "the wire said this", 400),
      setFormError,
      KNOWN_CODES,
      "fallback",
    );
    expect(result).toBe(false);
    expect(setFormError).toHaveBeenCalledWith("the wire said this");
  });

  it("uses the Error.message for plain Error instances", () => {
    const setFormError = vi.fn<(msg: string) => void>();
    const result = applyAppControlSubmitError(
      new Error("network blew up"),
      setFormError,
      KNOWN_CODES,
      "fallback",
    );
    expect(result).toBe(false);
    expect(setFormError).toHaveBeenCalledWith("network blew up");
  });

  it("uses the fallback for unknown thrown values", () => {
    const setFormError = vi.fn<(msg: string) => void>();
    const result = applyAppControlSubmitError(
      { weird: "object" },
      setFormError,
      KNOWN_CODES,
      "operation failed",
    );
    expect(result).toBe(false);
    expect(setFormError).toHaveBeenCalledWith("operation failed");
  });
});
