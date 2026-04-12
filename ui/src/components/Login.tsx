import { useState } from "react";
import { setApiKey, listHosts } from "../api";

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
    <div style={{ fontFamily: "system-ui, sans-serif", padding: "2rem", maxWidth: "20rem", margin: "4rem auto" }}>
      <h1 style={{ fontSize: "1.25rem", marginBottom: "1.5rem" }}>Fleet EDR</h1>
      <form onSubmit={(e) => { void handleSubmit(e); }}>
        <label htmlFor="api-key" style={{ display: "block", marginBottom: "0.5rem", fontSize: "0.9rem" }}>
          API key
        </label>
        <input
          id="api-key"
          type="password"
          value={key}
          onChange={(e) => { setKey(e.target.value); }}
          style={{ width: "100%", padding: "0.5rem", boxSizing: "border-box", marginBottom: "0.75rem" }}
          autoFocus
        />
        {error && <div style={{ color: "red", fontSize: "0.85rem", marginBottom: "0.75rem" }}>{error}</div>}
        <button type="submit" disabled={loading || key.length === 0} style={{ padding: "0.5rem 1.5rem" }}>
          {loading ? "Checking..." : "Log in"}
        </button>
      </form>
    </div>
  );
}
