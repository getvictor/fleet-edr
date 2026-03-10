import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { HostList } from "./components/HostList";
import { ProcessTreeView } from "./components/ProcessTree";

export function App() {
  return (
    <BrowserRouter basename="/ui">
      <div style={{ fontFamily: "system-ui, sans-serif", padding: "1rem" }}>
        <h1 style={{ fontSize: "1.25rem", marginBottom: "1rem" }}>
          Fleet EDR
        </h1>
        <Routes>
          <Route path="/" element={<HostList />} />
          <Route path="/hosts/:hostId" element={<ProcessTreeView />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </div>
    </BrowserRouter>
  );
}
