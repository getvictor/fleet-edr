// Per-line rule_type inference for the paste-many flow. The shapes mirror server/rules/internal/appcontrol/validate.go so the
// preview table renders the same rule_type the server would compute on submit. The operator can override the inferred type
// per-line before submission (the spec scenario for mixed identifiers requires it), so this module is advisory: an inferred
// type of null is "no shape matched" rather than an error.

// Phase A close-out gates CERTIFICATE and PATH behind the same "coming soon" flag the AddRuleModal renders. inference still
// returns those values when the shape matches so the operator sees that the row would map to a not-yet-supported type and can
// switch to BINARY (for a 64-hex) or omit the row (for a PATH) — instead of the row being silently rejected by the server.
const RULE_TYPE_CDHASH = "CDHASH";
const RULE_TYPE_BINARY = "BINARY";
const RULE_TYPE_TEAMID = "TEAMID";
const RULE_TYPE_SIGNINGID = "SIGNINGID";
const RULE_TYPE_CERTIFICATE = "CERTIFICATE";
const RULE_TYPE_PATH = "PATH";

const CDHASH_LENGTH = 40;
const BINARY_LENGTH = 64;
const TEAMID_LENGTH = 10;

const CDHASH_REGEX = /^[a-f0-9]{40}$/;
const BINARY_REGEX = /^[a-f0-9]{64}$/;
const TEAMID_REGEX = /^[A-Z0-9]{10}$/;
const SIGNINGID_REGEX = /^(?:[A-Z0-9]{10}|platform):[A-Za-z0-9._-]+$/;

// HINT_BINARY_COULD_BE_CERTIFICATE is the visible hint the spec calls out: a 64-hex value is the SHA-256 of either a Mach-O
// binary or a leaf certificate. The inferrer picks BINARY (the more common case in paste lists) and surfaces the alternate so
// the operator can switch the row's type before submit. The hint is the string the modal renders next to the type select.
export const HINT_BINARY_COULD_BE_CERTIFICATE = "Could also be CERTIFICATE";

// PasteInference is what the modal renders per parsed line. ruleType is null when no shape matches; the modal renders a
// "select a type" placeholder and disables submit until the operator picks one. hint is optional and surfaces only on
// shapes where the inferrer needs to flag an ambiguity.
export interface PasteInference {
  readonly raw: string;
  readonly identifier: string;
  readonly ruleType: string | null;
  readonly hint?: string;
}

// inferRuleType maps a single trimmed identifier to the rule_type the server's validators would accept. Order matters: the
// 10-character TEAMID check has to come before SIGNINGID because both can start with the same prefix.
export function inferRuleType(identifier: string): { ruleType: string | null; hint?: string } {
  if (identifier.length === CDHASH_LENGTH && CDHASH_REGEX.test(identifier)) {
    return { ruleType: RULE_TYPE_CDHASH };
  }
  if (identifier.length === BINARY_LENGTH && BINARY_REGEX.test(identifier)) {
    return { ruleType: RULE_TYPE_BINARY, hint: HINT_BINARY_COULD_BE_CERTIFICATE };
  }
  if (identifier.length === TEAMID_LENGTH && TEAMID_REGEX.test(identifier)) {
    return { ruleType: RULE_TYPE_TEAMID };
  }
  if (SIGNINGID_REGEX.test(identifier)) {
    return { ruleType: RULE_TYPE_SIGNINGID };
  }
  if (identifier.startsWith("/")) {
    return { ruleType: RULE_TYPE_PATH };
  }
  return { ruleType: null };
}

// parsePasteInput is the single entry the modal calls. Splits on newlines, strips blank lines (operators routinely paste from
// spreadsheets that leave trailing newlines), and feeds each remaining line through inferRuleType. Duplicate identifiers are
// NOT deduped here because the server's bulk-upsert validator rejects duplicate (rule_type, identifier) pairs inside one batch
// with a typed error; the modal surfaces that error verbatim so the operator sees which line is the offender.
export function parsePasteInput(input: string): PasteInference[] {
  const lines = input.split(/\r?\n/);
  const out: PasteInference[] = [];
  for (const raw of lines) {
    const identifier = raw.trim();
    if (identifier.length === 0) continue;
    const inference = inferRuleType(identifier);
    out.push({
      raw,
      identifier,
      ruleType: inference.ruleType,
      ...(inference.hint ? { hint: inference.hint } : {}),
    });
  }
  return out;
}

// EXPORTED constants for the modal so the type-select uses the same vocabulary. Ordered the way AddRuleModal renders the
// type select (BINARY first because demo cuts most often paste SHA-256s; CDHASH next; SIGNINGID + TEAMID after).
export const PASTE_MANY_RULE_TYPES = [
  RULE_TYPE_BINARY,
  RULE_TYPE_CDHASH,
  RULE_TYPE_SIGNINGID,
  RULE_TYPE_TEAMID,
  RULE_TYPE_CERTIFICATE,
  RULE_TYPE_PATH,
] as const;
