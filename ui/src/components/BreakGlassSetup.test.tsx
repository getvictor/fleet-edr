import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import { BreakGlassSetup } from "./BreakGlassSetup";
import * as auth from "../auth";

// BreakGlassSetup pins the token-driven redemption form: token-missing guard, the live
// password-length counter + submit-disabled gate, the begin → finish → navigate happy
// path, the redirect basename strip, each documented error reason → operator copy, and
// the WebAuthn-cancelled / generic-error branches.

const VALID_PASSWORD = "correct horse battery"; // > 12 runes.

function renderAt(initialPath = "/admin/break-glass/setup?token=abc") {
  return render(
    <MemoryRouter initialEntries={[initialPath]}>
      <Routes>
        <Route path="/admin/break-glass/setup" element={<BreakGlassSetup />} />
        <Route path="/" element={<div>HOME</div>} />
        <Route path="/alerts" element={<div>ALERTS</div>} />
      </Routes>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  vi.spyOn(auth, "breakglassBeginSetup").mockResolvedValue({ id: "attest" });
  vi.spyOn(auth, "breakglassFinishSetup").mockResolvedValue({ redirect: "/ui/" });
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("BreakGlassSetup form", () => {
  it("renders the password + credential-name inputs and the register button", () => {
    renderAt();
    expect(screen.getByLabelText(/^password$/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/security key name/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /register security key/i })).toBeInTheDocument();
  });

  it("shows the token-missing error and disables submit when no token is present", () => {
    renderAt("/admin/break-glass/setup");
    expect(screen.getByRole("alert")).toHaveTextContent(/missing its redemption token/i);
    expect(screen.getByRole("button", { name: /register security key/i })).toBeDisabled();
  });

  it("keeps submit disabled until the password meets the 12-rune minimum", () => {
    renderAt();
    const submit = screen.getByRole("button", { name: /register security key/i });
    expect(submit).toBeDisabled();
    fireEvent.change(screen.getByLabelText(/^password$/i), { target: { value: "short" } });
    expect(submit).toBeDisabled();
    fireEvent.change(screen.getByLabelText(/^password$/i), { target: { value: VALID_PASSWORD } });
    expect(submit).not.toBeDisabled();
  });

  it("updates the live character counter with the rune count", () => {
    renderAt();
    fireEvent.change(screen.getByLabelText(/^password$/i), { target: { value: "abcde" } });
    expect(screen.getByText(/5 \/ 12 characters/i)).toBeInTheDocument();
  });
});

describe("BreakGlassSetup submit happy path", () => {
  it("runs begin → finish → navigates to the stripped redirect", async () => {
    vi.mocked(auth.breakglassFinishSetup).mockResolvedValue({ redirect: "/ui/alerts" });
    renderAt();
    fireEvent.change(screen.getByLabelText(/^password$/i), { target: { value: VALID_PASSWORD } });
    fireEvent.change(screen.getByLabelText(/security key name/i), { target: { value: "my key" } });
    fireEvent.click(screen.getByRole("button", { name: /register security key/i }));

    await waitFor(() => { expect(auth.breakglassBeginSetup).toHaveBeenCalledWith("abc"); });
    await waitFor(() => { expect(auth.breakglassFinishSetup).toHaveBeenCalledWith("abc", VALID_PASSWORD, "my key", { id: "attest" }); });
    await waitFor(() => expect(screen.getByText("ALERTS")).toBeInTheDocument());
  });

  it("strips just /ui when the redirect is exactly /ui", async () => {
    vi.mocked(auth.breakglassFinishSetup).mockResolvedValue({ redirect: "/ui" });
    renderAt();
    fireEvent.change(screen.getByLabelText(/^password$/i), { target: { value: VALID_PASSWORD } });
    fireEvent.click(screen.getByRole("button", { name: /register security key/i }));
    await waitFor(() => expect(screen.getByText("HOME")).toBeInTheDocument());
  });
});

describe("BreakGlassSetup error mapping", () => {
  it.each([
    ["bootstrap.expired", /redemption link has expired/i],
    ["bootstrap.consumed", /already been used/i],
    ["rate_limited", /too many attempts from this address/i],
    ["challenge_missing", /setup session expired/i],
  ])("renders the directed copy for %s", async (reason, copyPattern) => {
    vi.mocked(auth.breakglassBeginSetup).mockRejectedValue(new auth.BreakglassError(400, reason));
    renderAt();
    fireEvent.change(screen.getByLabelText(/^password$/i), { target: { value: VALID_PASSWORD } });
    fireEvent.click(screen.getByRole("button", { name: /register security key/i }));
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent(copyPattern));
  });

  it("falls through to the generic message for an unmapped reason", async () => {
    vi.mocked(auth.breakglassFinishSetup).mockRejectedValue(new auth.BreakglassError(500, "weird"));
    renderAt();
    fireEvent.change(screen.getByLabelText(/^password$/i), { target: { value: VALID_PASSWORD } });
    fireEvent.click(screen.getByRole("button", { name: /register security key/i }));
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent(/setup failed/i));
  });

  it("renders the cancelled copy when registration throws NotAllowedError", async () => {
    vi.mocked(auth.breakglassBeginSetup).mockRejectedValue(new DOMException("cancelled", "NotAllowedError"));
    renderAt();
    fireEvent.change(screen.getByLabelText(/^password$/i), { target: { value: VALID_PASSWORD } });
    fireEvent.click(screen.getByRole("button", { name: /register security key/i }));
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent(/cancelled or timed out/i));
  });

  it("renders the generic message for a non-Breakglass non-NotAllowedError throw", async () => {
    vi.mocked(auth.breakglassBeginSetup).mockRejectedValue(new Error("network gone"));
    renderAt();
    fireEvent.change(screen.getByLabelText(/^password$/i), { target: { value: VALID_PASSWORD } });
    fireEvent.click(screen.getByRole("button", { name: /register security key/i }));
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent(/setup failed/i));
  });
});
