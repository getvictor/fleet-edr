// Phase 4c break-glass setup page: token-driven redemption form.
// Operator arrives via the printed redemption URL → server 302s to
// /ui/admin/break-glass/setup?token=X → this page mounts.
//
// Flow:
//   1. Read ?token= from the URL.
//   2. POST /admin/break-glass/setup/challenge to fetch the
//      registration challenge (server sets the signed challenge
//      cookie as part of the response).
//   3. Operator types a password (live ≥ 12-char counter) +
//      optional credential name.
//   4. Click "Register security key" → startRegistration()
//      prompts the authenticator → POST attestation +
//      password to /admin/break-glass/setup → server runs the
//      atomic redemption → 200 (with redirect target).
//   5. On success, navigate to the redirect target (typically
//      /ui/) so the freshly-minted session is exercised.

import { useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { Button } from "./ui/Button";
import { Card } from "./ui/Card";
import { Input } from "./ui/Input";
import {
  BreakglassError,
  breakglassBeginSetup,
  breakglassFinishSetup,
} from "../auth";
import "./Login.scss";

// MIN_PASSWORD_RUNES mirrors the server-side validator (Phase 4
// decision D: length-only ≥ 12). Live counter shows the operator
// how close they are without revealing the exact policy on the
// server side (server is the source of truth).
const MIN_PASSWORD_RUNES = 12;

// Friendly labels for the wire reasons returned by the redemption
// endpoint. Mirrors the breakglass package's reasonForSetupErr.
//
// Stored as a Map (rather than Record<string, string>) so the read
// site is `.get(reason)` instead of `setupErrorLabels[reason]` —
// eslint-plugin-security flags computed-property reads on plain
// objects as object-injection sinks when the key is server-derived.
const setupErrorLabels = new Map<string, string>([
  ["bootstrap.expired", "This redemption link has expired. Ask an administrator for a new one."],
  ["bootstrap.consumed", "This redemption link has already been used."],
  ["bootstrap.invalid", "This redemption link is invalid. Ask an administrator for a new one."],
  ["password.too_short", `Password must be at least ${String(MIN_PASSWORD_RUNES)} characters.`],
  ["challenge_missing", "Your setup session expired. Please reload this page and try again."],
  ["challenge_invalid", "Your setup session is invalid. Please reload this page and try again."],
  ["attestation_missing", "We didn't receive a security-key attestation. Please try again."],
  ["attestation_parse_failed", "We couldn't read your security-key attestation. Please try again."],
  ["rate_limited", "Too many attempts from this address. Wait a minute and try again."],
  ["setup_rate_limited", "Setup is rate-limited globally. Wait a minute and try again."],
  ["token_missing", "This page is missing its redemption token."],
]);

// runeCount counts Unicode code points (matches the server's
// utf8.RuneCountInString). Uses Array.from over the string iterator
// rather than [...s] because the spread operator's typed-array
// behavior in lint is conservative; Array.from(string) iterates
// code points the same way without tripping the security rule.
function runeCount(s: string): number {
  return Array.from(s).length;
}

type SetupPhase = "idle" | "registering" | "submitting";

// submitButtonLabel returns the user-visible button copy for the
// current setup phase. Extracted so the JSX is a single expression
// (Sonar S3358 flags nested ternaries inline).
function submitButtonLabel(phase: SetupPhase): string {
  if (phase === "registering") return "Touch your security key…";
  if (phase === "submitting") return "Saving…";
  return "Register security key";
}

export function BreakGlassSetup() {
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const token = params.get("token") ?? "";

  const [password, setPassword] = useState("");
  const [credentialName, setCredentialName] = useState("");
  // Initialise the error state from the token-missing branch
  // synchronously rather than via a useEffect setError dance — the
  // initial render already has the token, and a useEffect that sets
  // state on mount is exactly the cascading-render pattern lint
  // flags.
  const [error, setError] = useState<string | null>(
    token ? null : (setupErrorLabels.get("token_missing") ?? null),
  );
  const [busy, setBusy] = useState(false);
  const [phase, setPhase] = useState<SetupPhase>("idle");

  const passwordRuneLen = runeCount(password);
  const passwordMeetsMin = passwordRuneLen >= MIN_PASSWORD_RUNES;
  const submitDisabled = !token || !passwordMeetsMin || busy;

  async function handleSubmit(e: React.SyntheticEvent) {
    e.preventDefault();
    if (!token || !passwordMeetsMin) return;
    setError(null);
    setBusy(true);
    try {
      setPhase("registering");
      const attestation = await breakglassBeginSetup(token);
      setPhase("submitting");
      const result = await breakglassFinishSetup(
        token,
        password,
        credentialName.trim(),
        attestation,
      );
      // Navigate inside the basename-aware router. result.redirect
      // is "/ui/" — strip the basename so react-router doesn't
      // double-prefix it. The `===` plus `startsWith("/ui/")` guard
      // avoids mis-matching unrelated paths like /uipreview that
      // happen to share the substring.
      const dest =
        result.redirect === "/ui" || result.redirect.startsWith("/ui/")
          ? result.redirect.slice("/ui".length) || "/"
          : result.redirect;
      await navigate(dest, { replace: true });
    } catch (err) {
      if (err instanceof BreakglassError) {
        setError(setupErrorLabels.get(err.reason) ?? "Setup failed. Please try again.");
      } else if (err instanceof DOMException && err.name === "NotAllowedError") {
        setError("Security-key registration was cancelled or timed out. Please try again.");
      } else {
        setError("Setup failed. Please try again.");
      }
    } finally {
      setBusy(false);
      setPhase("idle");
    }
  }

  return (
    <div className="login-page">
      <Card padding="large" className="login-card">
        <div className="login-card__header">
          <span className="login-card__logo" aria-hidden="true">F</span>
          <h1 className="login-card__title">
            Break-glass <span className="login-card__accent">setup</span>
          </h1>
          <p className="login-card__subtitle">
            Set a recovery password and register a security key.
          </p>
        </div>

        {error && (
          <div className="login-card__error" role="alert">
            {error}
          </div>
        )}

        <form onSubmit={(e) => { void handleSubmit(e); }} className="login-card__form">
          <Input
            id="bg-password"
            label="Password"
            type="password"
            autoComplete="new-password"
            value={password}
            onChange={(e) => { setPassword(e.target.value); }}
            autoFocus
            disabled={busy || !token}
          />
          <div className="login-card__hint">
            {passwordRuneLen} / {MIN_PASSWORD_RUNES} characters
            {passwordMeetsMin ? " ✓" : ""}
          </div>
          <Input
            id="bg-credential-name"
            label="Security key name (optional)"
            type="text"
            autoComplete="off"
            value={credentialName}
            onChange={(e) => { setCredentialName(e.target.value); }}
            disabled={busy || !token}
          />
          <Button type="submit" fullWidth disabled={submitDisabled} isLoading={busy}>
            {submitButtonLabel(phase)}
          </Button>
        </form>
      </Card>
    </div>
  );
}
