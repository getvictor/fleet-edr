// Phase 4c login page: a single "Continue with Okta" call-to-action
// + a small "Break-glass login" footer link. Replaces the Phase
// 1-3 email/password form. Real users authenticate via OIDC; only
// the recovery account uses break-glass.
//
// Error rendering: when the OIDC callback handler fails (state
// mismatch, unknown subject, exchange failure, etc.) it 302s back
// to /ui/login?error=<reason>. We pull the reason off the URL and
// surface a directed message so the operator sees something more
// actionable than a generic 500.

import { useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Button } from "./ui/Button";
import { Card } from "./ui/Card";
import { oidcLoginUrl } from "../auth";
import "./Login.scss";

interface LoginProps {
  // Optional same-origin path the IdP returns to. Defaults to /ui/.
  readonly next?: string;
}

// errorMessages maps the wire reason header (set by the OIDC
// handler's error redirect) onto operator-readable copy. Stored as
// a Map so the read site is `errorMessages.get(reason)` rather than
// `errorMessages[reason]` — eslint-plugin-security's
// object-injection sink heuristic flags computed-property reads on
// plain objects, and the Map form sidesteps it cleanly.
const errorMessages = new Map<string, string>([
  ["invalid_state", "Your sign-in session expired before you returned. Please try again."],
  ["missing_state", "We couldn't verify your sign-in attempt. Please try again."],
  ["state_mismatch", "Your sign-in attempt didn't match. Please start over."],
  ["expired_state", "Your sign-in session expired. Please try again."],
  ["missing_code", "The identity provider didn't return a sign-in code. Please try again."],
  ["exchange_failed", "We couldn't reach the identity provider. Please try again in a moment."],
  ["unknown_subject", "Your identity provider account isn't authorised for this server. Contact an administrator."],
  ["email_conflict", "Another account already uses your email. Contact an administrator to merge access."],
  ["provision_failed", "We couldn't provision your account. Please try again or contact an administrator."],
  ["session_create_failed", "We couldn't start your session. Please try again."],
]);

export function Login({ next }: LoginProps) {
  const [params] = useSearchParams();
  const errorReason = params.get("error");
  // Memoise so the URL is built once per next-change rather than on
  // every render. The URL is the href of the call-to-action.
  const continueHref = useMemo(() => oidcLoginUrl(next ?? "/ui/"), [next]);

  // hint text rendered when the URL query carries an OIDC reason. We
  // accept the wire-shape strings 4a/4b emit; anything else falls
  // through to a generic message. The Map indirection keeps
  // eslint-plugin-security happy (the object-injection-sink
  // heuristic flags computed-property reads on plain objects).
  const errorHint = errorReason
    ? (errorMessages.get(errorReason) ?? "Sign-in failed. Please try again.")
    : null;

  // Track whether the operator clicked "Continue" so we can disable
  // the button while the browser navigates (UX nicety — without it
  // a slow IdP redirect leaves the user wondering whether the click
  // registered).
  const [navigating, setNavigating] = useState(false);

  return (
    <div className="login-page">
      <Card padding="large" className="login-card">
        <div className="login-card__header">
          <div className="login-card__brand">
            <span className="login-card__logo">F</span>
            <h1 className="login-card__title">
              Fleet <span className="login-card__accent">EDR</span>
            </h1>
          </div>
          <p className="login-card__subtitle">Sign in with your identity provider.</p>
        </div>

        {errorHint && (
          <div className="login-card__error" role="alert">
            {errorHint}
          </div>
        )}

        <Button
          type="button"
          isLoading={navigating}
          onClick={() => {
            setNavigating(true);
            globalThis.location.assign(continueHref);
          }}
        >
          Continue with single sign-on
        </Button>

        <div className="login-card__footer">
          <Link to="/admin/break-glass" className="login-card__break-glass">
            Break-glass login
          </Link>
        </div>
      </Card>
    </div>
  );
}
