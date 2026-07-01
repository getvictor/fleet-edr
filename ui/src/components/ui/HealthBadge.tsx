import { Badge, type BadgeVariant } from "./Badge";

// Map the server's agent-health rollup / component status to a Badge variant and a human label. Unknown or unrecognized values fall back
// to a neutral badge showing the raw string, so a future status the UI has not been taught still renders sensibly.
const HEALTH_VARIANTS: Record<string, BadgeVariant> = {
  healthy: "success",
  degraded: "medium",
  unhealthy: "critical",
  unknown: "neutral",
};

const HEALTH_LABELS: Record<string, string> = {
  healthy: "healthy",
  degraded: "degraded",
  unhealthy: "needs attention",
  unknown: "unknown",
};

export function HealthBadge({ status }: { readonly status: string }) {
  // The lookups index hardcoded constant tables by a small status string with a ?? fallback, so object-injection is a false positive
  // here (matching the disables in ProcessTree.tsx).
  // eslint-disable-next-line security/detect-object-injection
  const variant = HEALTH_VARIANTS[status] ?? "neutral";
  // eslint-disable-next-line security/detect-object-injection
  const label = HEALTH_LABELS[status] ?? status;
  return <Badge variant={variant}>{label}</Badge>;
}
