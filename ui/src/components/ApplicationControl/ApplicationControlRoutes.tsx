import { Routes, Route, Navigate } from "react-router-dom";
import { PoliciesList } from "./PoliciesList";
import { PolicyDetail } from "./PolicyDetail";

// ApplicationControlRoutes is the per-feature router under
// /app-control. Two pages today:
//   /app-control               → PoliciesList
//   /app-control/policies/:id  → PolicyDetail (with the rules table)
//
// Splitting the router into a feature-local component keeps App.tsx's
// outer Routes shallow and lets the Application Control surface grow
// (paste-many, host-groups, audit history) without filling up the
// top-level route table.
export function ApplicationControlRoutes() {
  return (
    <Routes>
      <Route path="/" element={<PoliciesList />} />
      <Route path="/policies/:id" element={<PolicyDetail />} />
      <Route path="*" element={<Navigate to="." replace />} />
    </Routes>
  );
}
