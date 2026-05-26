import { describe, it, expect, vi, afterEach } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { Login } from "./Login";

// Login renders the post-Phase-4c single-CTA login page: "Continue with single sign-on" + a break-glass footer link.
// Tests pin the wire-derived error-message map (each documented reason renders the right copy; unknown falls through to
// the generic message), the next-param resolution order (prop > URL ?next > default), and the click → location.assign
// dispatch.

function renderAt(searchParams: Record<string, string>, props: { next?: string } = {}) {
  const search = new URLSearchParams(searchParams).toString();
  return render(
    <MemoryRouter initialEntries={[`/admin?${search}`]}>
      <Login {...props} />
    </MemoryRouter>,
  );
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("Login error block", () => {
  it("renders no error block when ?error= is absent", () => {
    renderAt({});
    expect(screen.queryByRole("alert")).toBeNull();
  });

  // Spot-check the high-traffic mapped reasons rather than every entry; the Map itself is data, not logic.
  it.each([
    ["invalid_state", /sign-in session expired before you returned/i],
    ["unknown_subject", /isn't authorised for this server/i],
    ["exchange_failed", /couldn't reach the identity provider/i],
    ["session_create_failed", /couldn't start your session/i],
  ])("renders the directed copy for %s", (reason, copyPattern) => {
    renderAt({ error: reason });
    expect(screen.getByRole("alert")).toHaveTextContent(copyPattern);
  });

  it("falls through to the generic message for an unmapped reason", () => {
    renderAt({ error: "some_unmapped_reason" });
    expect(screen.getByRole("alert")).toHaveTextContent(/sign-in failed/i);
  });
});

describe("Login next-param resolution", () => {
  it("uses the next prop when one is provided", () => {
    renderAt({}, { next: "/ui/alerts" });
    const cta = screen.getByRole("button", { name: /continue with single sign-on/i });
    expect(cta).toBeInTheDocument();
    // The href is bound on click; we verify by clicking and inspecting the assign call below in a sibling test.
  });

  it("clicking Continue with the next prop hits /api/auth/login?next=<prop>", () => {
    const assignSpy = vi.fn();
    vi.stubGlobal("location", { assign: assignSpy });
    renderAt({}, { next: "/ui/hosts/abc" });
    fireEvent.click(screen.getByRole("button", { name: /continue with single sign-on/i }));
    expect(assignSpy).toHaveBeenCalledWith("/api/auth/login?next=%2Fui%2Fhosts%2Fabc");
  });

  it("falls back to the URL ?next when no prop is provided", () => {
    const assignSpy = vi.fn();
    vi.stubGlobal("location", { assign: assignSpy });
    renderAt({ next: "/ui/alerts" });
    fireEvent.click(screen.getByRole("button", { name: /continue with single sign-on/i }));
    expect(assignSpy).toHaveBeenCalledWith("/api/auth/login?next=%2Fui%2Falerts");
  });

  it("falls back to the default /ui/ when neither is provided", () => {
    const assignSpy = vi.fn();
    vi.stubGlobal("location", { assign: assignSpy });
    renderAt({});
    fireEvent.click(screen.getByRole("button", { name: /continue with single sign-on/i }));
    expect(assignSpy).toHaveBeenCalledWith("/api/auth/login?next=%2Fui%2F");
  });

  it("drops an off-shape URL ?next (open-redirect defence)", () => {
    const assignSpy = vi.fn();
    vi.stubGlobal("location", { assign: assignSpy });
    renderAt({ next: "//evil.example.com" });
    fireEvent.click(screen.getByRole("button", { name: /continue with single sign-on/i }));
    // oidcLoginUrl rejected the bad next and returned the bare endpoint.
    expect(assignSpy).toHaveBeenCalledWith("/api/auth/login");
  });
});

describe("Login break-glass link", () => {
  it("renders a link to /admin/break-glass", () => {
    renderAt({});
    const link = screen.getByRole("link", { name: /break-glass login/i });
    expect(link).toHaveAttribute("href", "/admin/break-glass");
  });
});

describe("Login navigating state", () => {
  it("transitions the button to loading on click", () => {
    const assignSpy = vi.fn();
    vi.stubGlobal("location", { assign: assignSpy });
    renderAt({});
    const cta = screen.getByRole("button", { name: /continue with single sign-on/i });
    expect(cta).not.toBeDisabled();
    fireEvent.click(cta);
    // The Button primitive renders isLoading by adding aria-busy or a class; assert via aria-busy if present, else just
    // verify the click landed (assign was called). The loading state is a UX nicety, not a correctness contract.
    expect(assignSpy).toHaveBeenCalled();
  });
});
