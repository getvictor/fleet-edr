import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import { BreakGlassLogin } from "./BreakGlassLogin";
import * as auth from "../auth";

// BreakGlassLogin pins the recovery-sign-in flow: email + password + WebAuthn assertion → POST /admin/break-glass.
// Tests cover form rendering, the happy-path submit chain, each documented error reason → operator copy, WebAuthn cancel,
// the redirect path-stripping logic (the helper strips "/ui" prefix so React Router navigates correctly), and the
// submit-disabled guard against empty inputs.

function renderAt(initialPath = "/admin/break-glass") {
  return render(
    <MemoryRouter initialEntries={[initialPath]}>
      <Routes>
        <Route path="/admin/break-glass" element={<BreakGlassLogin />} />
        {/* Sink routes so the post-login navigate doesn't blow up under the test router. */}
        <Route path="/" element={<div>HOME</div>} />
        <Route path="/alerts" element={<div>ALERTS</div>} />
      </Routes>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  // Default happy-path stubs; individual tests override via mockImplementation / mockRejectedValue.
  vi.spyOn(auth, "breakglassBeginLogin").mockResolvedValue({ id: "asrt" });
  vi.spyOn(auth, "breakglassFinishLogin").mockResolvedValue({ redirect: "/ui/" });
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("BreakGlassLogin form", () => {
  it("renders email + password + submit + back-link", () => {
    renderAt();
    expect(screen.getByLabelText(/email/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/password/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /sign in with security key/i })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /back to single sign-on/i })).toHaveAttribute("href", "/login");
  });

  it("submit is disabled until both email + password are entered", () => {
    renderAt();
    const submit = screen.getByRole("button", { name: /sign in with security key/i });
    expect(submit).toBeDisabled();

    fireEvent.change(screen.getByLabelText(/email/i), { target: { value: "ops@example.com" } });
    expect(submit).toBeDisabled(); // still missing password

    fireEvent.change(screen.getByLabelText(/password/i), { target: { value: "pw" } });
    expect(submit).not.toBeDisabled();
  });

  it("trims the email before submission (a leading space shouldn't enable submit prematurely)", () => {
    renderAt();
    fireEvent.change(screen.getByLabelText(/email/i), { target: { value: "   " } });
    fireEvent.change(screen.getByLabelText(/password/i), { target: { value: "pw" } });
    expect(screen.getByRole("button", { name: /sign in with security key/i })).toBeDisabled();
  });
});

describe("BreakGlassLogin submit happy path", () => {
  it("calls breakglassBeginLogin → breakglassFinishLogin → navigates to the redirect", async () => {
    const finishSpy = vi.spyOn(auth, "breakglassFinishLogin").mockResolvedValue({ redirect: "/ui/alerts" });
    renderAt();

    fireEvent.change(screen.getByLabelText(/email/i), { target: { value: "  ops@example.com  " } });
    fireEvent.change(screen.getByLabelText(/password/i), { target: { value: "pw" } });
    fireEvent.click(screen.getByRole("button", { name: /sign in with security key/i }));

    await waitFor(() => { expect(auth.breakglassBeginLogin).toHaveBeenCalledWith("ops@example.com"); });
    await waitFor(() => { expect(finishSpy).toHaveBeenCalledWith("ops@example.com", "pw", { id: "asrt" }); });
    // /ui/alerts → /alerts (the basename strip; the sink route is at /alerts).
    await waitFor(() => expect(screen.getByText("ALERTS")).toBeInTheDocument());
  });

  it("strips just /ui when the redirect is exactly /ui (no trailing slash)", async () => {
    vi.spyOn(auth, "breakglassFinishLogin").mockResolvedValue({ redirect: "/ui" });
    renderAt();
    fireEvent.change(screen.getByLabelText(/email/i), { target: { value: "ops@example.com" } });
    fireEvent.change(screen.getByLabelText(/password/i), { target: { value: "pw" } });
    fireEvent.click(screen.getByRole("button", { name: /sign in with security key/i }));
    // /ui → "/" (slice("/ui".length) is empty; fallback to "/")
    await waitFor(() => expect(screen.getByText("HOME")).toBeInTheDocument());
  });

  it("does NOT strip a redirect that isn't /ui-prefixed (e.g. /uipreview)", async () => {
    vi.spyOn(auth, "breakglassFinishLogin").mockResolvedValue({ redirect: "/uipreview" });
    renderAt();
    fireEvent.change(screen.getByLabelText(/email/i), { target: { value: "ops@example.com" } });
    fireEvent.change(screen.getByLabelText(/password/i), { target: { value: "pw" } });
    fireEvent.click(screen.getByRole("button", { name: /sign in with security key/i }));
    // /uipreview stays /uipreview. There's no sink route so the test just verifies no crash + we land on a navigated path
    // (no longer the break-glass form). The router's catch-all returns an empty render, so we look for the absence of the
    // form's heading.
    await waitFor(() => expect(screen.queryByText(/break-glass/i)).not.toBeInTheDocument());
  });
});

describe("BreakGlassLogin error mapping", () => {
  it.each([
    ["invalid_credentials", /invalid email, password, or security key/i],
    ["no_credentials", /no security key is registered/i],
    ["rate_limited", /too many attempts from this address/i],
    ["email_rate_limited", /too many failed attempts for this email/i],
    ["assertion_parse_failed", /couldn't read your security-key response/i],
  ])("renders the directed copy for %s", async (reason, copyPattern) => {
    vi.spyOn(auth, "breakglassBeginLogin").mockRejectedValue(
      new auth.BreakglassError(401, reason),
    );
    renderAt();
    fireEvent.change(screen.getByLabelText(/email/i), { target: { value: "ops@example.com" } });
    fireEvent.change(screen.getByLabelText(/password/i), { target: { value: "pw" } });
    fireEvent.click(screen.getByRole("button", { name: /sign in with security key/i }));
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent(copyPattern));
  });

  it("falls through to the generic message for an unmapped reason", async () => {
    vi.spyOn(auth, "breakglassBeginLogin").mockRejectedValue(
      new auth.BreakglassError(500, "some_unmapped_reason"),
    );
    renderAt();
    fireEvent.change(screen.getByLabelText(/email/i), { target: { value: "ops@example.com" } });
    fireEvent.change(screen.getByLabelText(/password/i), { target: { value: "pw" } });
    fireEvent.click(screen.getByRole("button", { name: /sign in with security key/i }));
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent(/sign-in failed/i));
  });

  it("renders the WebAuthn-cancelled copy when startAuthentication throws NotAllowedError", async () => {
    vi.spyOn(auth, "breakglassBeginLogin").mockRejectedValue(
      new DOMException("user cancelled", "NotAllowedError"),
    );
    renderAt();
    fireEvent.change(screen.getByLabelText(/email/i), { target: { value: "ops@example.com" } });
    fireEvent.change(screen.getByLabelText(/password/i), { target: { value: "pw" } });
    fireEvent.click(screen.getByRole("button", { name: /sign in with security key/i }));
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent(/security-key sign-in was cancelled/i));
  });

  it("renders the generic message for a non-BreakglassError non-NotAllowedError throw", async () => {
    vi.spyOn(auth, "breakglassBeginLogin").mockRejectedValue(new Error("network gone"));
    renderAt();
    fireEvent.change(screen.getByLabelText(/email/i), { target: { value: "ops@example.com" } });
    fireEvent.change(screen.getByLabelText(/password/i), { target: { value: "pw" } });
    fireEvent.click(screen.getByRole("button", { name: /sign in with security key/i }));
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent(/sign-in failed/i));
  });
});
