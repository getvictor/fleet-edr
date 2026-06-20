import { useEffect, useState } from "react";
import { getSSOConfig, updateSSOConfig, testSSOConnection, type SSOConfig } from "../../api";
import { PageHeader } from "../ui/PageHeader";
import { Card } from "../ui/Card";
import { Button } from "../ui/Button";
import { Input, Select } from "../ui/Input";
import { Toggle } from "../ui/Toggle";
import { Badge } from "../ui/Badge";
import "./SSOSettings.scss";

// The redirect URI is derived from the external URL and shown read-only; the operator
// registers exactly this value at the IdP. Mirrors the server's RedirectURLFor.
const CALLBACK_PATH = "/api/auth/callback";

function deriveRedirect(externalURL: string): string {
  const raw = externalURL.trim();
  if (raw === "") return "";
  try {
    // Parse rather than concatenate so a query string or fragment on the base can't bleed into the path and produce a
    // malformed callback (e.g. "https://e.example.com?x=1/api/auth/callback"). Mirrors the server's RedirectURLFor.
    const u = new URL(raw);
    u.search = "";
    u.hash = "";
    u.pathname = u.pathname.replace(/\/+$/, "") + CALLBACK_PATH;
    return u.toString();
  } catch {
    return "";
  }
}

function isHTTPURL(raw: string): boolean {
  try {
    const u = new URL(raw.trim());
    return (u.protocol === "http:" || u.protocol === "https:") && u.host !== "";
  } catch {
    return false;
  }
}

// hasQueryOrFragment flags external URLs carrying a query string or fragment; the redirect URI is derived from the bare
// origin + path, so a query/fragment can't be round-tripped and must be rejected before save. A raw scan (rather than
// URL.search/hash, which drop a bare trailing "?"/"#") keeps this in lockstep with the server's validation.
function hasQueryOrFragment(raw: string): boolean {
  const trimmed = raw.trim();
  return trimmed.includes("?") || trimmed.includes("#");
}

// editable mirrors the operator-editable fields; the secret is write-only (empty unless
// the operator is rotating it).
interface FormState {
  issuer: string;
  clientID: string;
  externalURL: string;
  secret: string;
  jitEnabled: boolean;
  defaultRole: string;
}

function toForm(cfg: SSOConfig): FormState {
  return {
    issuer: cfg.issuer,
    clientID: cfg.client_id,
    externalURL: cfg.external_url,
    secret: "",
    jitEnabled: cfg.jit_enabled,
    defaultRole: cfg.default_role || "analyst",
  };
}

type TestResult = { ok: boolean; reason?: string } | null;

export function SSOSettings() {
  const [config, setConfig] = useState<SSOConfig | null>(null);
  const [form, setForm] = useState<FormState | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<TestResult>(null);

  useEffect(() => {
    let cancelled = false;
    getSSOConfig()
      .then((cfg) => {
        if (cancelled) return;
        setConfig(cfg);
        setForm(toForm(cfg));
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load SSO configuration");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => { cancelled = true; };
  }, []);

  if (loading) return <div className="sso-settings__status">Loading...</div>;
  if (error) return <div className="sso-settings__status sso-settings__status--error">Error: {error}</div>;
  if (!form || !config) return <div className="sso-settings__status">No configuration available.</div>;

  const scopes = config.scopes && config.scopes.length > 0 ? config.scopes : ["openid", "email", "profile"];
  const redirectURL = deriveRedirect(form.externalURL);

  function update<K extends keyof FormState>(key: K, value: FormState[K]) {
    setForm((prev) => (prev ? { ...prev, [key]: value } : prev));
    setSaved(false);
    // A prior connection-test verdict was for the old issuer/external URL; clear it so the UI never shows a stale
    // "verified" against fields the operator has since edited.
    setTestResult(null);
  }

  function validate(f: FormState): string | null {
    if (!isHTTPURL(f.issuer)) return "Issuer must be a valid http(s) URL.";
    if (f.clientID.trim() === "") return "Client ID is required.";
    if (!isHTTPURL(f.externalURL)) return "External URL must be a valid http(s) URL.";
    if (hasQueryOrFragment(f.externalURL)) return "External URL must not contain a query string or fragment.";
    return null;
  }

  async function handleSave() {
    if (!form) return;
    const invalid = validate(form);
    if (invalid) {
      setSaveError(invalid);
      return;
    }
    setSaving(true);
    setSaveError(null);
    setSaved(false);
    // Trim before the rotate check so a whitespace-only entry is treated as "keep" rather than rotating the stored
    // secret to blanks (which would silently break SSO logins).
    const secret = form.secret.trim();
    try {
      const updated = await updateSSOConfig({
        issuer: form.issuer.trim(),
        client_id: form.clientID.trim(),
        // Omit the secret unless the operator entered a new value (write-only rotate).
        ...(secret !== "" ? { client_secret: secret } : {}),
        external_url: form.externalURL.trim(),
        scopes,
        jit_enabled: form.jitEnabled,
        default_role: form.defaultRole,
      });
      setConfig(updated);
      setForm(toForm(updated));
      setSaved(true);
    } catch (err: unknown) {
      setSaveError(err instanceof Error ? err.message : "Failed to save settings.");
    } finally {
      setSaving(false);
    }
  }

  function handleCancel() {
    if (config) setForm(toForm(config));
    setSaveError(null);
    setSaved(false);
    setTestResult(null);
  }

  async function handleTest() {
    if (!form) return;
    // Validate locally first so a malformed issuer surfaces a clear message instead of a generic 400 from the probe endpoint.
    if (!isHTTPURL(form.issuer)) {
      setTestResult({ ok: false, reason: "Issuer must be a valid http(s) URL." });
      return;
    }
    setTesting(true);
    setTestResult(null);
    try {
      setTestResult(await testSSOConnection(form.issuer.trim()));
    } catch (err: unknown) {
      setTestResult({ ok: false, reason: err instanceof Error ? err.message : "Connection test failed." });
    } finally {
      setTesting(false);
    }
  }

  async function handleCopyRedirect() {
    // navigator.clipboard is undefined in insecure contexts / older browsers (the lib types declare it always-present, hence
    // the cast); the field stays selectable as a fallback.
    const clipboard = navigator.clipboard as Clipboard | undefined;
    if (!clipboard) return;
    try {
      await clipboard.writeText(redirectURL);
    } catch {
      // Clipboard can be unavailable (insecure context); the field is selectable as a fallback.
    }
  }

  return (
    <form className="sso-settings" onSubmit={(e) => { e.preventDefault(); void handleSave(); }}>
      <PageHeader
        title="Single sign-on"
        subtitle="Operators sign in through your OpenID Connect provider. One identity provider is configured per deployment."
        actions={config.configured
          ? <Badge variant="success">Configured</Badge>
          : <Badge variant="neutral">Not configured</Badge>}
      />

      <Card padding="large">
        <div className="sso-settings__card-head">
          <h2 className="sso-settings__card-title">OpenID Connect</h2>
          <Button type="button" variant="inverse" size="small" onClick={() => { void handleTest(); }} isLoading={testing}>
            Test connection
          </Button>
        </div>

        {testResult !== null && (
          <div
            className={testResult.ok ? "sso-settings__test sso-settings__test--ok" : "sso-settings__test sso-settings__test--fail"}
            role="status"
          >
            {testResult.ok ? "Connection verified: discovery and token endpoint reachable." : `Connection failed: ${testResult.reason ?? "unreachable"}`}
          </div>
        )}

        <div className="sso-settings__grid">
          <Input
            id="sso-issuer"
            label="Issuer URL"
            type="text"
            placeholder="https://acme.okta.com"
            value={form.issuer}
            onChange={(e) => { update("issuer", e.target.value); }}
          />
          <Input
            id="sso-client-id"
            label="Client ID"
            type="text"
            placeholder="0oa8x2k4mWq1ZpL5d7"
            value={form.clientID}
            onChange={(e) => { update("clientID", e.target.value); }}
          />

          <Input
            id="sso-external-url"
            label="External URL"
            type="text"
            placeholder="https://edr.acme.com"
            value={form.externalURL}
            onChange={(e) => { update("externalURL", e.target.value); }}
            aria-describedby="sso-external-url-help"
          />
          <p id="sso-external-url-help" className="sso-settings__help">
            Your deployment&apos;s externally-reachable base URL. The redirect URI below is derived from it.
          </p>

          <div className="sso-settings__field-full">
            <span className="field__label">Redirect URL</span>
            <div className="sso-settings__readonly-row">
              <input
                className="field__input sso-settings__readonly"
                type="text"
                readOnly
                aria-label="Redirect URL"
                value={redirectURL}
              />
              <Button type="button" variant="inverse" size="small" onClick={() => { void handleCopyRedirect(); }} disabled={redirectURL === ""}>
                Copy
              </Button>
            </div>
            <p className="sso-settings__help">
              Register this exact value as a sign-in redirect URI on the provider. Trailing slashes and case must match.
            </p>
          </div>

          <div className="sso-settings__field-full">
            <Input
              id="sso-secret"
              label="Client secret"
              type="password"
              autoComplete="new-password"
              placeholder={config.secret_set ? "•••••• enter a new value to rotate" : "enter the client secret"}
              value={form.secret}
              onChange={(e) => { update("secret", e.target.value); }}
            />
            <p className="sso-settings__help">Write-only. Enter a new value to rotate; leave blank to keep the current secret.</p>
          </div>

          <div className="sso-settings__field-full">
            <span className="field__label">Scopes</span>
            <div className="sso-settings__chips">
              {scopes.map((s) => <span key={s} className="sso-settings__chip">{s}</span>)}
            </div>
            <p className="sso-settings__help">Group-to-role mapping (the groups scope) ships in a future release.</p>
          </div>
        </div>
      </Card>

      <Card padding="large">
        <div className="sso-settings__jit">
          <div>
            <h2 className="sso-settings__card-title">Just-in-time provisioning</h2>
            <p className="sso-settings__help">
              When on, anyone who signs in through the provider is auto-created and given the default role. When off, an operator must be invited first.
            </p>
          </div>
          <Toggle
            id="sso-jit"
            aria-label="Just-in-time provisioning"
            checked={form.jitEnabled}
            onChange={(e) => { update("jitEnabled", e.target.checked); }}
          />
        </div>
        <div className="sso-settings__jit-role">
          <Select
            id="sso-default-role"
            label="Default role for new SSO users"
            value={form.defaultRole}
            onChange={(e) => { update("defaultRole", e.target.value); }}
            inline
          >
            <option value="analyst">Analyst</option>
            <option value="auditor">Auditor</option>
          </Select>
          <p className="sso-settings__help">Never auto-grant admin from an SSO claim.</p>
        </div>
      </Card>

      <div className="sso-settings__callout" role="note">
        <strong>Break-glass account stays available.</strong> If the provider is unreachable, the break-glass admin can still sign in via the
        Break-glass login link on the login page. The surface is IP-allowlist gated, so off-network callers never see it.
      </div>

      {saveError !== null && <div className="sso-settings__save-error" role="alert">{saveError}</div>}
      {saved && <div className="sso-settings__saved" role="status">Settings saved.</div>}

      <div className="sso-settings__footer">
        <Button type="submit" variant="primary" isLoading={saving}>Save changes</Button>
        <Button type="button" variant="inverse" onClick={handleCancel} disabled={saving}>Cancel</Button>
      </div>
    </form>
  );
}
