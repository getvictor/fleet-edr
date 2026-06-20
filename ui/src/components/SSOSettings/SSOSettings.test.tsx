import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import * as api from "../../api";
import { SSOSettings } from "./SSOSettings";

const baseConfig: api.SSOConfig = {
  configured: true,
  issuer: "https://acme.okta.com",
  client_id: "0oa8x2k4mWq1ZpL5d7",
  external_url: "https://edr.acme.com",
  redirect_url: "https://edr.acme.com/api/auth/callback",
  scopes: ["openid", "email", "profile"],
  jit_enabled: true,
  default_role: "analyst",
  secret_set: true,
};

afterEach(() => {
  vi.restoreAllMocks();
});

describe("SSOSettings", () => {
  // spec:sso-configuration/the-single-sign-on-admin-settings-page/secret-field-never-shows-the-stored-secret
  it("loads and renders the provider config with a derived read-only redirect", async () => {
    vi.spyOn(api, "getSSOConfig").mockResolvedValue(baseConfig);
    render(<SSOSettings />);

    expect(await screen.findByLabelText("Issuer URL")).toHaveValue("https://acme.okta.com");
    expect(screen.getByLabelText("Client ID")).toHaveValue("0oa8x2k4mWq1ZpL5d7");
    expect(screen.getByLabelText("External URL")).toHaveValue("https://edr.acme.com");
    expect(screen.getByLabelText("Redirect URL")).toHaveValue("https://edr.acme.com/api/auth/callback");
    expect(screen.getByLabelText("Redirect URL")).toHaveAttribute("readonly");
    expect(screen.getByText("Configured")).toBeInTheDocument();
    // Secret is write-only: the field is empty with a rotate affordance, never the stored value.
    expect(screen.getByLabelText("Client secret")).toHaveValue("");
    expect(screen.getByLabelText("Client secret")).toHaveAttribute("placeholder", expect.stringContaining("rotate"));
    // Scopes render as read-only chips.
    for (const s of baseConfig.scopes ?? []) expect(screen.getByText(s)).toBeInTheDocument();
  });

  it("derives the redirect URL live as the external URL changes", async () => {
    vi.spyOn(api, "getSSOConfig").mockResolvedValue(baseConfig);
    render(<SSOSettings />);
    await screen.findByLabelText("External URL");
    fireEvent.change(screen.getByLabelText("External URL"), { target: { value: "https://edr.example.org/" } });
    // Trailing slash tolerated; callback appended.
    expect(screen.getByLabelText("Redirect URL")).toHaveValue("https://edr.example.org/api/auth/callback");
  });

  it("omits client_secret on save when the field is left blank (keep)", async () => {
    vi.spyOn(api, "getSSOConfig").mockResolvedValue(baseConfig);
    const upd = vi.spyOn(api, "updateSSOConfig").mockResolvedValue(baseConfig);
    render(<SSOSettings />);
    await screen.findByLabelText("Issuer URL");

    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
    await waitFor(() => { expect(upd).toHaveBeenCalledTimes(1); });
    expect(upd.mock.calls[0][0]).not.toHaveProperty("client_secret");
    expect(await screen.findByText("Settings saved.")).toBeInTheDocument();
  });

  it("includes client_secret on save when a new value is entered (rotate)", async () => {
    vi.spyOn(api, "getSSOConfig").mockResolvedValue(baseConfig);
    const upd = vi.spyOn(api, "updateSSOConfig").mockResolvedValue(baseConfig);
    render(<SSOSettings />);
    await screen.findByLabelText("Client secret");

    fireEvent.change(screen.getByLabelText("Client secret"), { target: { value: "rotated-secret" } });
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
    await waitFor(() => { expect(upd).toHaveBeenCalledTimes(1); });
    expect(upd.mock.calls[0][0]).toMatchObject({ client_secret: "rotated-secret" });
  });

  it("blocks save and shows an error on an invalid issuer", async () => {
    vi.spyOn(api, "getSSOConfig").mockResolvedValue(baseConfig);
    const upd = vi.spyOn(api, "updateSSOConfig").mockResolvedValue(baseConfig);
    render(<SSOSettings />);
    await screen.findByLabelText("Issuer URL");

    fireEvent.change(screen.getByLabelText("Issuer URL"), { target: { value: "not a url" } });
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/Issuer must be a valid/);
    expect(upd).not.toHaveBeenCalled();
  });

  it("surfaces a save error from the server", async () => {
    vi.spyOn(api, "getSSOConfig").mockResolvedValue(baseConfig);
    vi.spyOn(api, "updateSSOConfig").mockRejectedValue(new Error("API error: 409"));
    render(<SSOSettings />);
    await screen.findByLabelText("Issuer URL");
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("API error: 409");
  });

  it("runs a connection test and renders the verified result", async () => {
    vi.spyOn(api, "getSSOConfig").mockResolvedValue(baseConfig);
    const test = vi.spyOn(api, "testSSOConnection").mockResolvedValue({ ok: true });
    render(<SSOSettings />);
    await screen.findByLabelText("Issuer URL");

    fireEvent.click(screen.getByRole("button", { name: "Test connection" }));
    expect(await screen.findByText(/Connection verified/)).toBeInTheDocument();
    expect(test).toHaveBeenCalledWith("https://acme.okta.com");
  });

  it("renders a failed connection test with its reason", async () => {
    vi.spyOn(api, "getSSOConfig").mockResolvedValue(baseConfig);
    vi.spyOn(api, "testSSOConnection").mockResolvedValue({ ok: false, reason: "discovery unreachable" });
    render(<SSOSettings />);
    await screen.findByLabelText("Issuer URL");
    fireEvent.click(screen.getByRole("button", { name: "Test connection" }));
    expect(await screen.findByText(/discovery unreachable/)).toBeInTheDocument();
  });

  it("toggles JIT and selects the default role", async () => {
    vi.spyOn(api, "getSSOConfig").mockResolvedValue(baseConfig);
    const upd = vi.spyOn(api, "updateSSOConfig").mockResolvedValue(baseConfig);
    render(<SSOSettings />);
    await screen.findByLabelText("Issuer URL");

    const jit = screen.getByRole("switch", { name: "Just-in-time provisioning" });
    expect(jit).toBeChecked();
    fireEvent.click(jit);
    fireEvent.change(screen.getByLabelText("Default role for new SSO users"), { target: { value: "auditor" } });

    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
    await waitFor(() => { expect(upd).toHaveBeenCalledTimes(1); });
    expect(upd.mock.calls[0][0]).toMatchObject({ jit_enabled: false, default_role: "auditor" });
  });

  it("shows Not configured when no provider is set up", async () => {
    vi.spyOn(api, "getSSOConfig").mockResolvedValue({
      ...baseConfig,
      configured: false,
      issuer: "",
      client_id: "",
      external_url: "",
      secret_set: false,
    });
    render(<SSOSettings />);
    expect(await screen.findByText("Not configured")).toBeInTheDocument();
    expect(screen.getByLabelText("Client secret")).toHaveAttribute("placeholder", "enter the client secret");
  });

  it("renders the load error state", async () => {
    vi.spyOn(api, "getSSOConfig").mockRejectedValue(new Error("boom"));
    render(<SSOSettings />);
    expect(await screen.findByText(/Error: boom/)).toBeInTheDocument();
  });

  it("falls back to default scopes when the server returns null scopes", async () => {
    // A nil Go slice serializes to JSON null; the page must not crash dereferencing .length.
    vi.spyOn(api, "getSSOConfig").mockResolvedValue({ ...baseConfig, scopes: null });
    render(<SSOSettings />);
    await screen.findByLabelText("Issuer URL");
    for (const s of ["openid", "email", "profile"]) expect(screen.getByText(s)).toBeInTheDocument();
  });

  it("strips a query/fragment from the derived redirect and blocks save on such an external URL", async () => {
    vi.spyOn(api, "getSSOConfig").mockResolvedValue(baseConfig);
    const upd = vi.spyOn(api, "updateSSOConfig").mockResolvedValue(baseConfig);
    render(<SSOSettings />);
    await screen.findByLabelText("External URL");

    fireEvent.change(screen.getByLabelText("External URL"), { target: { value: "https://edr.example.org/?x=1#frag" } });
    // Redirect is derived from origin + path only; the query/fragment never leak into the callback.
    expect(screen.getByLabelText("Redirect URL")).toHaveValue("https://edr.example.org/api/auth/callback");

    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/must not contain a query string or fragment/);
    expect(upd).not.toHaveBeenCalled();
  });

  it("omits a whitespace-only client_secret rather than rotating to blanks", async () => {
    vi.spyOn(api, "getSSOConfig").mockResolvedValue(baseConfig);
    const upd = vi.spyOn(api, "updateSSOConfig").mockResolvedValue(baseConfig);
    render(<SSOSettings />);
    await screen.findByLabelText("Client secret");

    fireEvent.change(screen.getByLabelText("Client secret"), { target: { value: "   " } });
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
    await waitFor(() => { expect(upd).toHaveBeenCalledTimes(1); });
    expect(upd.mock.calls[0][0]).not.toHaveProperty("client_secret");
  });

  it("validates the issuer before calling the test-connection endpoint", async () => {
    vi.spyOn(api, "getSSOConfig").mockResolvedValue(baseConfig);
    const test = vi.spyOn(api, "testSSOConnection").mockResolvedValue({ ok: true });
    render(<SSOSettings />);
    await screen.findByLabelText("Issuer URL");

    fireEvent.change(screen.getByLabelText("Issuer URL"), { target: { value: "not a url" } });
    fireEvent.click(screen.getByRole("button", { name: "Test connection" }));
    expect(await screen.findByText(/Issuer must be a valid/)).toBeInTheDocument();
    expect(test).not.toHaveBeenCalled();
  });

  it("clears a stale connection-test result when a field is edited", async () => {
    vi.spyOn(api, "getSSOConfig").mockResolvedValue(baseConfig);
    vi.spyOn(api, "testSSOConnection").mockResolvedValue({ ok: true });
    render(<SSOSettings />);
    await screen.findByLabelText("Issuer URL");

    fireEvent.click(screen.getByRole("button", { name: "Test connection" }));
    expect(await screen.findByText(/Connection verified/)).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Issuer URL"), { target: { value: "https://other.okta.com" } });
    expect(screen.queryByText(/Connection verified/)).not.toBeInTheDocument();
  });

  it("reverts edits on Cancel", async () => {
    vi.spyOn(api, "getSSOConfig").mockResolvedValue(baseConfig);
    render(<SSOSettings />);
    await screen.findByLabelText("Issuer URL");

    fireEvent.change(screen.getByLabelText("Issuer URL"), { target: { value: "https://edited.okta.com" } });
    expect(screen.getByLabelText("Issuer URL")).toHaveValue("https://edited.okta.com");
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(screen.getByLabelText("Issuer URL")).toHaveValue("https://acme.okta.com");
  });

  it("surfaces a thrown error from the test-connection endpoint", async () => {
    vi.spyOn(api, "getSSOConfig").mockResolvedValue(baseConfig);
    vi.spyOn(api, "testSSOConnection").mockRejectedValue(new Error("network down"));
    render(<SSOSettings />);
    await screen.findByLabelText("Issuer URL");

    fireEvent.click(screen.getByRole("button", { name: "Test connection" }));
    expect(await screen.findByText(/network down/)).toBeInTheDocument();
  });

  it("copies the redirect URL when the clipboard API is available", async () => {
    vi.spyOn(api, "getSSOConfig").mockResolvedValue(baseConfig);
    const writeText = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal("navigator", { clipboard: { writeText } });
    render(<SSOSettings />);
    await screen.findByLabelText("Issuer URL");

    fireEvent.click(screen.getByRole("button", { name: "Copy" }));
    await waitFor(() => { expect(writeText).toHaveBeenCalledWith("https://edr.acme.com/api/auth/callback"); });
    vi.unstubAllGlobals();
  });

  it("does not throw when copying without a clipboard API", async () => {
    vi.spyOn(api, "getSSOConfig").mockResolvedValue(baseConfig);
    vi.stubGlobal("navigator", {});
    render(<SSOSettings />);
    await screen.findByLabelText("Issuer URL");

    expect(() => { fireEvent.click(screen.getByRole("button", { name: "Copy" })); }).not.toThrow();
    vi.unstubAllGlobals();
  });
});
