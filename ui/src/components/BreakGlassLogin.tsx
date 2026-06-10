// Break-glass login page. Operator arrives via the
// "Break-glass login" footer link on /ui/login (or by typing
// /admin/break-glass directly, which the server 302s to
// /ui/admin/break-glass).
//
// Flow:
//   1. Operator types email + password.
//   2. Click "Sign in with security key" →
//      POST /admin/break-glass/challenge {email} → server returns
//      assertion options + sets the signed challenge cookie.
//   3. startAuthentication() prompts the authenticator.
//   4. POST /admin/break-glass with email + password + assertion.
//   5. On success, navigate to /ui/.
//
// The server collapses every failure mode (unknown email, wrong
// password, no credentials, sign_count regression) onto an
// X-Edr-Auth-Reason of "invalid_credentials" so the wire response
// can't be used to enumerate accounts. The audit trail records
// the precise reason.

import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Button } from "./ui/Button";
import { Card } from "./ui/Card";
import { Input } from "./ui/Input";
import {
  BreakglassError,
  breakglassBeginLogin,
  breakglassFinishLogin,
} from "../auth";
import "./Login.scss";

// Reason -> message indirection. Stored as a Map (rather than a plain
// Record<string, string>) so the read site is `.get(reason)` instead
// of `loginErrorLabels[reason]`: eslint-plugin-security flags
// computed-property reads on plain objects as object-injection sinks
// when the key is server-derived. Same shape Login.tsx uses for the
// OIDC error reasons.
const loginErrorLabels = new Map<string, string>([
  ["invalid_credentials", "Invalid email, password, or security key."],
  ["no_credentials", "No security key is registered for this account."],
  ["challenge_missing", "Your sign-in session expired. Please try again."],
  ["challenge_invalid", "Your sign-in session is invalid. Please try again."],
  ["body_invalid", "We couldn't read your sign-in data. Please try again."],
  ["assertion_parse_failed", "We couldn't read your security-key response. Please try again."],
  ["rate_limited", "Too many attempts from this address. Wait a minute and try again."],
  ["email_rate_limited", "Too many failed attempts for this email. Wait a minute and try again."],
]);

export function BreakGlassLogin() {
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submitDisabled = !email.trim() || !password || busy;

  async function handleSubmit(e: React.SyntheticEvent) {
    e.preventDefault();
    if (submitDisabled) return;
    setError(null);
    setBusy(true);
    try {
      const assertion = await breakglassBeginLogin(email.trim());
      const result = await breakglassFinishLogin(email.trim(), password, assertion);
      // Strip the basename only when result.redirect is exactly /ui or
      // a /ui/-prefixed path. A bare startsWith("/ui") would mis-match
      // unrelated paths like /uipreview, slicing off "/ui" and routing
      // somewhere unintended.
      const dest =
        result.redirect === "/ui" || result.redirect.startsWith("/ui/")
          ? result.redirect.slice("/ui".length) || "/"
          : result.redirect;
      await navigate(dest, { replace: true });
    } catch (err) {
      if (err instanceof BreakglassError) {
        setError(loginErrorLabels.get(err.reason) ?? "Sign-in failed. Please try again.");
      } else if (err instanceof DOMException && err.name === "NotAllowedError") {
        setError("Security-key sign-in was cancelled or timed out. Please try again.");
      } else {
        setError("Sign-in failed. Please try again.");
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login-page">
      <Card padding="large" className="login-card">
        <div className="login-card__header">
          <span className="login-card__logo" aria-hidden="true">F</span>
          <h1 className="login-card__title">
            Break-glass <span className="login-card__accent">sign-in</span>
          </h1>
          <p className="login-card__subtitle">
            Recovery sign-in with email + password + security key.
          </p>
        </div>

        {error && (
          <div className="login-card__error" role="alert">
            {error}
          </div>
        )}

        <form onSubmit={(e) => { void handleSubmit(e); }} className="login-card__form">
          <Input
            id="bg-email"
            label="Email"
            type="email"
            autoComplete="username"
            value={email}
            onChange={(e) => { setEmail(e.target.value); }}
            autoFocus
            disabled={busy}
          />
          <Input
            id="bg-password"
            label="Password"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => { setPassword(e.target.value); }}
            disabled={busy}
          />
          <Button type="submit" fullWidth disabled={submitDisabled} isLoading={busy}>
            {busy ? "Signing in…" : "Sign in with security key"}
          </Button>
        </form>

        <div className="login-card__footer">
          <Link to="/login" className="login-card__break-glass">
            Back to single sign-on
          </Link>
        </div>
      </Card>
    </div>
  );
}
