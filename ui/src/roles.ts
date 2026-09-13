// BINDABLE_ROLES are the seeded roles an admin may bind to a user or a service account. super_admin is intentionally absent: the UI never
// grants it (only a super_admin may, via break-glass / SQL), and rows that already hold it render read-only.
export const BINDABLE_ROLES = [
  { value: "analyst", label: "Analyst" },
  { value: "senior_analyst", label: "Senior analyst" },
  { value: "auditor", label: "Auditor" },
  { value: "admin", label: "Admin" },
] as const;

const ROLE_LABELS = new Map<string, string>([
  ...BINDABLE_ROLES.map((r): [string, string] => [r.value, r.label]),
  ["super_admin", "Super admin"],
  ["", "No role"],
]);

// roleLabel renders a role id as the label every surface shows for it, and an id this build does not know as itself.
export function roleLabel(role: string): string {
  return ROLE_LABELS.get(role) ?? role;
}
