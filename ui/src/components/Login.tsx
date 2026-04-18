import { useState } from "react";
import { setApiKey, listHosts } from "../api";
import { Button } from "./ui/Button";
import { Card } from "./ui/Card";
import { Input } from "./ui/Input";
import "./Login.scss";

interface LoginProps {
  onLogin: () => void;
}

export function Login({ onLogin }: LoginProps) {
  const [key, setKey] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: React.SyntheticEvent) {
    e.preventDefault();
    setError("");
    setLoading(true);

    setApiKey(key);
    try {
      await listHosts();
      onLogin();
    } catch {
      setApiKey("");
      setError("Invalid API key");
    } finally {
      setLoading(false);
    }
  }

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
            Enter your API key to sign in
          </p>
        </div>

        <form onSubmit={(e) => { void handleSubmit(e); }} className="login-card__form">
          <Input
            id="api-key"
            label="API key"
            type="password"
            value={key}
            onChange={(e) => { setKey(e.target.value); }}
            autoFocus
          />
          {error && <div className="login-card__error">{error}</div>}
          <Button
            type="submit"
            disabled={key.length === 0}
            isLoading={loading}
          >
            {loading ? "Checking..." : "Log in"}
          </Button>
        </form>
      </Card>
    </div>
  );
}
