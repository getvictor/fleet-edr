// RULE_MODE_LABELS names the modes a rule runs in, shared by every page that shows one so the names cannot drift apart. A Map rather than
// an object literal, so a mode string the server sends that this client does not know renders as sent instead of resolving an inherited
// object key.
const RULE_MODE_LABELS: ReadonlyMap<string, string> = new Map([
  ["alert", "Alert"],
  ["monitor", "Monitor"],
  ["disabled", "Disabled"],
]);

// ruleModeLabel returns the reader-facing name of a mode, or the mode itself when this client does not recognise it.
export function ruleModeLabel(mode: string): string {
  return RULE_MODE_LABELS.get(mode) ?? mode;
}
