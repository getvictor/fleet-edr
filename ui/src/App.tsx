import { useState } from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { HostList } from "./components/HostList";
import { ProcessTreeView } from "./components/ProcessTree";
import { AlertList } from "./components/AlertList";
import { Login } from "./components/Login";
import { TopNav } from "./components/ui/TopNav";

export function App() {
  const [authenticated, setAuthenticated] = useState(
    () => sessionStorage.getItem("edr_api_key") !== null,
  );

  if (!authenticated) {
    return <Login onLogin={() => { setAuthenticated(true); }} />;
  }

  return (
    <BrowserRouter basename="/ui">
      <TopNav />
      <main className="app-page">
        <Routes>
          <Route path="/" element={<HostList />} />
          <Route path="/alerts" element={<AlertList />} />
          <Route path="/hosts/:hostId" element={<ProcessTreeView />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </BrowserRouter>
  );
}
