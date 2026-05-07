// ReauthModal — Phase 5 inline reauth prompt. Wired by useReauthRetry
// when a destructive action lands on a stale session: the chokepoint
// returns 403 + reauth_required, the hook catches it, this modal
// renders, and on completion the original mutation retries once.
//
// Two flows behind one component, dispatched on the server-supplied
// challenge.authMethod:
//   - "local_password" (break-glass): password input + WebAuthn
//     ceremony against /api/auth/reauth, no full-page navigation.
//   - "oidc": "Continue" button → reauthOIDC() does a full-page
//     redirect to /api/auth/login?reauth=1&next=<current URL>; the
//     IdP forces a fresh credential prompt via prompt=login. The
//     React tree unmounts during the redirect; the operator returns
//     to the same URL with a fresh session and can re-click the
//     destructive button.
//
// Cancellation surfaces the original gate-deny back through the
// hook's `resolve(false)` so the wrapped mutation's onError fires —
// the operator deserves to know the action did not land.

import { useState } from "react";
import { Button } from "./ui/Button";
import { Card } from "./ui/Card";
import { Input } from "./ui/Input";
import { BreakglassError, reauthBreakglass, reauthOIDC } from "../auth";
import type { ReauthModalProps } from "../hooks/useReauthRetry";
import "./Login.scss";

// reauthErrorLabels maps the wire reasons the break-glass reauth POST
// returns onto operator-readable copy. Stored as a Map for the same
// reason BreakGlassLogin's labels are: eslint-plugin-security flags
// computed-property reads on plain objects when the key is server-
// derived.
const reauthErrorLabels = new Map<string, string>([
  ["invalid_credentials", "Invalid password or security key."],
  ["no_credentials", "No security key is registered for this account."],
  ["challenge_missing", "Your reauth session expired. Please try again."],
  ["challenge_invalid", "Your reauth session is invalid. Please try again."],
  ["assertion_parse_failed", "We couldn't read your security-key response. Please try again."],
  ["rate_limited", "Too many attempts from this address. Wait a minute and try again."],
  ["email_rate_limited", "Too many failed attempts. Wait a minute and try again."],
  ["reauth_not_supported", "This session can't reauth here. Please sign out and back in."],
]);

export function ReauthModal({ open, challenge, resolve }: ReauthModalProps) {
  if (!open || !challenge) return null;
  // Modal renders one of two flows. The wrapping <div> is the
  // backdrop; clicks on it cancel (same as the explicit Cancel
  // button) so accidental destructive-action clicks have a
  // low-friction back-out path.
  return (
    <div className="reauth-backdrop" role="dialog" aria-modal="true">
      <Card padding="large" className="login-card reauth-card">
        {challenge.authMethod === "oidc" ? (
          <OIDCReauthFlow resolve={resolve} />
        ) : (
          <BreakglassReauthFlow resolve={resolve} />
        )}
      </Card>
    </div>
  );
}

function OIDCReauthFlow({ resolve }: { readonly resolve: (ok: boolean) => void }) {
  const [navigating, setNavigating] = useState(false);
  return (
    <>
      <div className="login-card__header">
        <h2 className="login-card__title">Confirm your identity</h2>
        <p className="login-card__subtitle">
          This action requires a fresh sign-in. Continue to your identity
          provider to confirm, then re-run the action.
        </p>
      </div>
      <Button
        type="button"
        isLoading={navigating}
        onClick={() => {
          setNavigating(true);
          // reauthOIDC() never returns — it replaces the document via
          // location.assign. The resolve(true) path here is purely
          // for code shape; the page is already navigating away.
          reauthOIDC();
        }}
      >
        Continue with single sign-on
      </Button>
      <Button type="button" variant="text-link" onClick={() => { resolve(false); }}>
        Cancel
      </Button>
    </>
  );
}

function BreakglassReauthFlow({ resolve }: { readonly resolve: (ok: boolean) => void }) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submitDisabled = !password || busy;

  async function handleSubmit(e: React.SyntheticEvent) {
    e.preventDefault();
    if (submitDisabled) return;
    setError(null);
    setBusy(true);
    try {
      await reauthBreakglass(password);
      resolve(true);
    } catch (err) {
      if (err instanceof BreakglassError) {
        setError(reauthErrorLabels.get(err.reason) ?? "Reauth failed. Please try again.");
      } else if (err instanceof DOMException && err.name === "NotAllowedError") {
        setError("Security-key prompt was cancelled or timed out. Please try again.");
      } else {
        setError("Reauth failed. Please try again.");
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <div className="login-card__header">
        <h2 className="login-card__title">Confirm your identity</h2>
        <p className="login-card__subtitle">
          Re-enter your break-glass password and touch your security key
          to continue.
        </p>
      </div>

      {error && (
        <div className="login-card__error" role="alert">
          {error}
        </div>
      )}

      <form onSubmit={(e) => { void handleSubmit(e); }} className="login-card__form">
        <Input
          id="reauth-password"
          label="Password"
          type="password"
          autoComplete="current-password"
          value={password}
          onChange={(e) => { setPassword(e.target.value); }}
          autoFocus
          disabled={busy}
        />
        <Button type="submit" disabled={submitDisabled} isLoading={busy}>
          {busy ? "Confirming…" : "Confirm with security key"}
        </Button>
        <Button type="button" variant="text-link" disabled={busy} onClick={() => { resolve(false); }}>
          Cancel
        </Button>
      </form>
    </>
  );
}
