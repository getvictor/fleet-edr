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
      <Route index element={<PoliciesList />} />
      <Route path="policies/:id" element={<PolicyDetail />} />
      {/*
          Catch-all falls back to the parent's index route (the
          policies list). Using an explicit "/app-control" target so
          a malformed link like /app-control/garbage lands on the
          list page rather than the home page or the relative
          fallback's risk of a redirect loop (Copilot flagged the
          absolute-path-in-nested-Routes shape).
      */}
      <Route path="*" element={<Navigate to="/app-control" replace />} />
    </Routes>
  );
}
