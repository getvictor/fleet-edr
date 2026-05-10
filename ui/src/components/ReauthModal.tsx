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
//     redirect to the server-supplied reauthURL with &next=<current
//     path> appended so the IdP returns the operator to the page
//     that triggered the reauth_required.
//
// Renders as a native <dialog> opened via showModal() so the browser
// provides backdrop, focus trap, and Escape-to-cancel for free. The
// onCancel handler maps Escape + the mirrored backdrop click onto
// resolve(false) — cancellation surfaces the original gate-deny back
// through the hook so the wrapped mutation's onError fires (rather
// than silent success).

import { useCallback, useEffect, useRef, useState } from "react";
import { Button } from "./ui/Button";
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

const DIALOG_TITLE_ID = "reauth-modal-title";

export function ReauthModal({ open, challenge, resolve }: Readonly<ReauthModalProps>) {
  const dialogRef = useRef<HTMLDialogElement>(null);

  // Open / close the native dialog imperatively. showModal() is what
  // gives us the backdrop, focus trap, and Escape-to-cancel
  // semantics; the declarative `open` attribute would render a
  // non-modal dialog without those affordances.
  useEffect(() => {
    const dlg = dialogRef.current;
    if (!dlg) return;
    if (open && !dlg.open) {
      dlg.showModal();
    } else if (!open && dlg.open) {
      dlg.close();
    }
  }, [open]);

  // Backdrop click cancels. Wired imperatively rather than via a JSX
  // onClick attribute on the <dialog>: jsx-a11y/eslint flags
  // onClick/onKeyDown directly on a <dialog> as event handlers on a
  // "non-interactive element" (the rule's allowlist predates wide
  // <dialog> support). The native modal IS interactive; addEventListener
  // attaches the same behaviour without tripping the heuristic. The
  // mechanism exploited is that the ::backdrop pseudo-element bubbles
  // a click on the dialog itself, so e.target === dlg means the
  // operator clicked outside the card content.
  useEffect(() => {
    const dlg = dialogRef.current;
    if (!dlg) return undefined;
    const onBackdropClick = (e: MouseEvent) => {
      if (e.target === dlg) resolve(false);
    };
    dlg.addEventListener("click", onBackdropClick);
    return () => { dlg.removeEventListener("click", onBackdropClick); };
  }, [resolve]);

  // The dialog's `cancel` event fires on Escape; route it through
  // resolve(false) so cancellation has one path. preventDefault
  // suppresses the browser's default "cancel + close" so React stays
  // in charge of the open-state transition. onCancel isn't a generic
  // mouse/keyboard handler and is allowed in JSX.
  const handleCancel = useCallback((e: React.SyntheticEvent<HTMLDialogElement>) => {
    e.preventDefault();
    resolve(false);
  }, [resolve]);

  if (!challenge) return null;
  return (
    <dialog
      ref={dialogRef}
      className="reauth-dialog login-card"
      aria-labelledby={DIALOG_TITLE_ID}
      onCancel={handleCancel}
    >
      {challenge.authMethod === "oidc" ? (
        <OIDCReauthFlow reauthURL={challenge.reauthURL} resolve={resolve} />
      ) : (
        <BreakglassReauthFlow resolve={resolve} />
      )}
    </dialog>
  );
}

interface OIDCReauthFlowProps {
  readonly reauthURL: string;
  readonly resolve: (ok: boolean) => void;
}

function OIDCReauthFlow({ reauthURL, resolve }: Readonly<OIDCReauthFlowProps>) {
  const [navigating, setNavigating] = useState(false);
  return (
    <>
      <div className="login-card__header">
        <h2 id={DIALOG_TITLE_ID} className="login-card__title">Confirm your identity</h2>
        <p className="login-card__subtitle">
          This action requires a fresh sign-in. Continue to your identity
          provider to confirm, then re-run the action.
        </p>
      </div>
      <Button
        type="button"
        fullWidth
        isLoading={navigating}
        onClick={() => {
          setNavigating(true);
          // reauthOIDC navigates the page away; control doesn't
          // return here in any meaningful sense. The setNavigating
          // above is purely UX (button shows the loading state for
          // the brief moment before the document unmounts).
          reauthOIDC(reauthURL);
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

interface BreakglassReauthFlowProps {
  readonly resolve: (ok: boolean) => void;
}

function BreakglassReauthFlow({ resolve }: Readonly<BreakglassReauthFlowProps>) {
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
        <h2 id={DIALOG_TITLE_ID} className="login-card__title">Confirm your identity</h2>
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
        <Button type="submit" fullWidth disabled={submitDisabled} isLoading={busy}>
          {busy ? "Confirming…" : "Confirm with security key"}
        </Button>
        <Button type="button" variant="text-link" disabled={busy} onClick={() => { resolve(false); }}>
          Cancel
        </Button>
      </form>
    </>
  );
}
