import { useState } from "react";
import { login, Unauthorized401Error } from "../api";
import { Button } from "./ui/Button";
import { Card } from "./ui/Card";
import { Input } from "./ui/Input";
import "./Login.scss";

interface LoginProps {
  onLogin: () => void;
}

// Phase 3 login: email + password → POST /api/v1/session → server sets HttpOnly
// session cookie and returns the per-session CSRF token. api.ts stashes the CSRF in
// sessionStorage; App.tsx re-renders with the logged-in view.
export function Login({ onLogin }: LoginProps) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: React.SyntheticEvent) {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      await login(email.trim(), password);
      onLogin();
    } catch (err) {
      if (err instanceof Unauthorized401Error) {
        // The server returns a generic 401 for both "unknown email" and "wrong
        // password" so the UI cannot be used to enumerate accounts. Show the same.
        setError("Invalid email or password.");
      } else {
        setError("Sign-in failed. Please try again.");
      }
    } finally {
      setLoading(false);
    }
  }

  const submitDisabled = email.length === 0 || password.length === 0;

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
          <p className="login-card__subtitle">
            Sign in with your admin email and password
          </p>
        </div>

        <form onSubmit={(e) => { void handleSubmit(e); }} className="login-card__form">
          <Input
            id="email"
            label="Email"
            type="email"
            autoComplete="username"
            value={email}
            onChange={(e) => { setEmail(e.target.value); }}
            autoFocus
          />
          <Input
            id="password"
            label="Password"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => { setPassword(e.target.value); }}
          />
          {error && <div className="login-card__error">{error}</div>}
          <Button
            type="submit"
            disabled={submitDisabled}
            isLoading={loading}
          >
            {loading ? "Signing in…" : "Sign in"}
          </Button>
        </form>
      </Card>
    </div>
  );
}
