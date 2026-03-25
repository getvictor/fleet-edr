import { useState } from "react";
import { BrowserRouter, Routes, Route, Navigate, Link, useLocation } from "react-router-dom";
import { HostList } from "./components/HostList";
import { ProcessTreeView } from "./components/ProcessTree";
import { AlertList } from "./components/AlertList";
import { Login } from "./components/Login";

function Nav() {
  const location = useLocation();
  const isAlerts = location.pathname === "/alerts";
  return (
    <div style={{ display: "flex", alignItems: "center", gap: "1.5rem", marginBottom: "1rem" }}>
      <h1 style={{ fontSize: "1.25rem", margin: 0 }}>Fleet EDR</h1>
      <nav style={{ display: "flex", gap: "1rem", fontSize: "0.9rem" }}>
        <Link to="/" style={{ fontWeight: location.pathname === "/" ? "bold" : "normal" }}>Hosts</Link>
        <Link to="/alerts" style={{ fontWeight: isAlerts ? "bold" : "normal" }}>Alerts</Link>
      </nav>
    </div>
  );
}

export function App() {
  const [authenticated, setAuthenticated] = useState(() => sessionStorage.getItem("edr_api_key") !== null);

  if (!authenticated) {
    return <Login onLogin={() => setAuthenticated(true)} />;
  }

  return (
    <BrowserRouter basename="/ui">
      <div style={{ fontFamily: "system-ui, sans-serif", padding: "1rem" }}>
        <Nav />
        <Routes>
          <Route path="/" element={<HostList />} />
          <Route path="/alerts" element={<AlertList />} />
          <Route path="/hosts/:hostId" element={<ProcessTreeView />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </div>
    </BrowserRouter>
  );
}
