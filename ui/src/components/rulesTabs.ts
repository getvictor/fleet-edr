import type { SubNavItem } from "./ui/SubNav";

// The surfaces of the Rules section. Coverage is computed entirely from the registered rules and names them on every technique
// row, so the two are views of one corpus rather than two destinations; they are listed here once so both render the same row.
export const RULES_TABS: readonly SubNavItem[] = [
  { to: "/rules", label: "Rules" },
  { to: "/coverage", label: "ATT&CK coverage" },
];

export const RULES_TABS_LABEL = "Rules views";
