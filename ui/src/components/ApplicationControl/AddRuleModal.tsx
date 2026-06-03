import { useCallback, useEffect, useState } from "react";
import {
  createAppControlRule,
  type CreateAppControlRuleRequest,
} from "../../api";
import { useReauthRetry } from "../../hooks/useReauthRetry";
import { ReauthModal } from "../ReauthModal";
import { Input, Select } from "../ui/Input";
import { AppControlDialogShell } from "./AppControlDialogShell";
import { applyAppControlSubmitError } from "./dialogErrors";
import "./ApplicationControl.scss";

// AddRuleModalProps is the parent contract. open drives showModal() /
// close(); onClose fires on Cancel/Escape; onCreated fires after a
// successful POST so the parent can re-fetch the policy.
interface AddRuleModalProps {
  readonly open: boolean;
  readonly policyID: number;
  readonly onClose: () => void;
  readonly onCreated: () => void;
}

const DIALOG_TITLE_ID = "add-rule-modal-title";

// RULE_TYPES enumerates the values the schema's rule_type ENUM accepts. All six ship in
// v0.1.0: BINARY, CDHASH, SIGNINGID, and TEAMID (PR #289) plus CERTIFICATE and PATH
// (PR #210, "expand rule types beyond BINARY"). The server validates every type
// (server/rules/internal/appcontrol/validate.go) and the extension's AUTH_EXEC decider
// enforces the precedence walk CDHASH > BINARY > CERTIFICATE > SIGNINGID > TEAMID > PATH.
const RULE_TYPES: { value: string; label: string; available: boolean }[] = [
  { value: "BINARY", label: "BINARY (file SHA-256)", available: true },
  { value: "CDHASH", label: "CDHASH (code-directory hash)", available: true },
  { value: "SIGNINGID", label: "SIGNINGID (Team:bundle.id)", available: true },
  { value: "TEAMID", label: "TEAMID (Apple Developer team)", available: true },
  { value: "CERTIFICATE", label: "CERTIFICATE (leaf SHA-256)", available: true },
  { value: "PATH", label: "PATH (canonical absolute)", available: true },
];

const SEVERITIES = ["low", "medium", "high", "critical"];

// Server-validator mirrors. Each regex matches the canonical shape per
// server/rules/internal/appcontrol/validate.go. Catching format errors client-side gives
// the operator immediate feedback instead of a round trip + typed 400.
const BINARY_HEX_LENGTH = 64;
const CDHASH_HEX_LENGTH = 40;
const BINARY_HEX_REGEX = /^[a-f0-9]{64}$/;
const CDHASH_HEX_REGEX = /^[a-f0-9]{40}$/;
const TEAM_ID_REGEX = /^[A-Z0-9]{10}$/;
const SIGNING_ID_REGEX = /^(?:[A-Z0-9]{10}|platform):[A-Za-z0-9._-]+$/;

// PLACEHOLDERS gives each rule type a hint string the identifier field renders. Helps an
// operator pasting a value see immediately whether they grabbed the right shape. Stored as
// a Map so the type→string lookup never trips the object-injection lint.
const PLACEHOLDERS = new Map<string, string>([
  ["BINARY", "64 lowercase hex characters (sha256)"],
  ["CDHASH", "40 lowercase hex characters"],
  ["TEAMID", "10 uppercase alphanumeric (e.g. EQHXZ8M8AV)"],
  ["SIGNINGID", "EQHXZ8M8AV:com.google.Chrome or platform:com.apple.curl"],
  ["CERTIFICATE", "64 lowercase hex characters (leaf cert sha256)"],
  ["PATH", "absolute path, e.g. /usr/local/bin/app (/tmp,/var,/etc canonicalized to /private)"],
]);

// hexValidator builds a per-type validator for the fixed-length lowercase-hex shapes (BINARY, CDHASH, CERTIFICATE). Returns
// null on success or a user-facing error string. Factored out so each rule type is a tiny function behind the dispatch Map
// below, keeping validateIdentifier a flat lookup (Sonar typescript:S3776 cognitive-complexity).
function hexValidator(label: string, len: number, regex: RegExp): (trimmed: string) => string | null {
  return (trimmed) => {
    if (trimmed.length !== len) {
      return `${label} identifier must be ${String(len)} hex characters (was ${String(trimmed.length)}).`;
    }
    if (!regex.test(trimmed.toLowerCase())) {
      return `${label} identifier must contain only hex characters (0-9 a-f); will be normalized to lowercase before submit.`;
    }
    return null;
  };
}

// validatePath rejects the shapes the server's canonicalizePath rejects outright: relative paths and `..` segments. The empty
// case is caught by validateIdentifier; the server canonicalizes the rest on persist (/tmp,/var,/etc -> /private).
function validatePath(trimmed: string): string | null {
  if (!trimmed.startsWith("/")) return "PATH must be an absolute path (start with /).";
  if (trimmed.split("/").includes("..")) return "PATH must not contain `..` segments.";
  return null;
}

// IDENTIFIER_VALIDATORS maps each rule type to its format check. CERTIFICATE shares BINARY's 64-char SHA-256 hex shape (the
// leaf signing cert's digest; the server uses the same hex64 regex). A Map keeps the dispatch off bracket-indexing (object-injection lint).
const IDENTIFIER_VALIDATORS = new Map<string, (trimmed: string) => string | null>([
  ["BINARY", hexValidator("BINARY", BINARY_HEX_LENGTH, BINARY_HEX_REGEX)],
  ["CERTIFICATE", hexValidator("CERTIFICATE", BINARY_HEX_LENGTH, BINARY_HEX_REGEX)],
  ["CDHASH", hexValidator("CDHASH", CDHASH_HEX_LENGTH, CDHASH_HEX_REGEX)],
  ["TEAMID", (trimmed) => (TEAM_ID_REGEX.test(trimmed) ? null : "TEAMID must be 10 uppercase alphanumeric characters (e.g. EQHXZ8M8AV).")],
  ["SIGNINGID", (trimmed) => (SIGNING_ID_REGEX.test(trimmed) ? null : "SIGNINGID must look like <TeamID>:<bundle.id> or platform:<bundle.id>.")],
  ["PATH", validatePath],
]);

// validateIdentifier trims, rejects empty, then dispatches to the per-type validator. Returns null on success or a user-facing
// error string. Identifiers are normalized at submit (BINARY/CDHASH/CERTIFICATE lowercased; TEAMID/SIGNINGID kept
// case-sensitive; PATH canonicalized server-side).
function validateIdentifier(ruleType: string, value: string): string | null {
  const trimmed = value.trim();
  if (trimmed.length === 0) return "Identifier is required.";
  const validate = IDENTIFIER_VALIDATORS.get(ruleType);
  if (!validate) return `Rule type ${ruleType} is not accepted by this build.`;
  return validate(trimmed);
}

// normalizeIdentifier prepares the value for submission to the server. BINARY, CDHASH, and
// CERTIFICATE are lowercased (the server validator is strict on hex case); TEAMID and
// SIGNINGID stay untouched because the format already constrains them. PATH is sent as
// typed; the server canonicalizes it on persist (NormalizeIdentifier in validate.go).
function normalizeIdentifier(ruleType: string, value: string): string {
  const trimmed = value.trim();
  if (ruleType === "BINARY" || ruleType === "CDHASH" || ruleType === "CERTIFICATE") {
    return trimmed.toLowerCase();
  }
  return trimmed;
}

// errorMessageForCode maps the server's typed application_control.*
// error codes onto operator-readable copy. Anything unrecognised
// falls back to the raw message the server returned (already
// human-readable) so we don't black-hole unexpected failures.
const errorMessageByCode = new Map<string, string>([
  ["application_control.invalid_rule", "The rule didn't pass server-side validation."],
  ["application_control.duplicate_rule", "A rule with this identifier already exists in this policy."],
  ["application_control.policy_not_found", "The policy was deleted before the rule could be saved."],
  ["application_control.invalid_policy_id", "Invalid policy id."],
  ["application_control.invalid_json", "The request body was not valid JSON."],
]);

export function AddRuleModal({ open, policyID, onClose, onCreated }: AddRuleModalProps) {
  const [ruleType, setRuleType] = useState("BINARY");
  const [identifier, setIdentifier] = useState("");
  const [severity, setSeverity] = useState("medium");
  const [customMsg, setCustomMsg] = useState("");
  const [customURL, setCustomURL] = useState("");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  // Reset the form whenever the dialog opens. Otherwise a Cancel + re-open would surface the previous attempt's values.
  useEffect(() => {
    if (!open) return;
    // eslint-disable-next-line react-hooks/set-state-in-effect -- intentional reset tied to the open prop transition
    setRuleType("BINARY");
    setIdentifier("");
    setSeverity("medium");
    setCustomMsg("");
    setCustomURL("");
    setReason("");
    setBusy(false);
    setFormError(null);
  }, [open]);

  const submitCreate = useCallback(
    (req: CreateAppControlRuleRequest) => createAppControlRule(policyID, req),
    [policyID],
  );
  const { call: callCreate, modal: reauthModal } = useReauthRetry(submitCreate);

  const submitDisabled = busy || reason.trim().length === 0 || identifier.trim().length === 0;

  async function handleSubmit(e: React.SyntheticEvent) {
    e.preventDefault();
    if (submitDisabled) return;
    const validation = validateIdentifier(ruleType, identifier);
    if (validation) {
      setFormError(validation);
      return;
    }
    // The host-app modal only renders "More info" for http/https URLs (BlockAlert.swift rejects other schemes so a hostile rule
    // author can't trigger arbitrary URL handlers from a single click). Enforce the same posture client-side.
    const trimmedURL = customURL.trim();
    if (trimmedURL.length > 0) {
      try {
        const parsed = new URL(trimmedURL);
        if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
          setFormError("More info URL must use http or https.");
          return;
        }
      } catch {
        setFormError("More info URL is not a valid URL.");
        return;
      }
    }
    setFormError(null);
    setBusy(true);
    try {
      const req: CreateAppControlRuleRequest = {
        rule_type: ruleType,
        identifier: normalizeIdentifier(ruleType, identifier),
        severity,
        reason: reason.trim(),
      };
      if (customMsg.trim().length > 0) req.custom_msg = customMsg.trim();
      if (customURL.trim().length > 0) req.custom_url = customURL.trim();
      await callCreate(req);
      onCreated();
    } catch (err) {
      if (applyAppControlSubmitError(err, setFormError, errorMessageByCode, "Failed to create rule.")) {
        return;
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <AppControlDialogShell
      open={open}
      onClose={onClose}
      titleId={DIALOG_TITLE_ID}
      title="Add rule"
      subtitle="Block an executable on every assigned host. The rule fans out to enrolled agents on save."
      formError={formError}
      busy={busy}
      submitDisabled={submitDisabled}
      submitLabel="Save rule"
      onSubmit={(e) => { void handleSubmit(e); }}
      reauthModal={<ReauthModal {...reauthModal} />}
    >
      <Select
        id="rule-type"
        label="Type"
        inline={false}
        value={ruleType}
        onChange={(e) => { setRuleType(e.target.value); }}
        disabled={busy}
      >
        {RULE_TYPES.map((t) => (
          <option
            key={t.value}
            value={t.value}
            disabled={!t.available}
          >
            {t.label}{t.available ? "" : " (coming soon)"}
          </option>
        ))}
      </Select>

      <Input
        id="rule-identifier"
        label="Identifier"
        type="text"
        autoComplete="off"
        spellCheck={false}
        placeholder={PLACEHOLDERS.get(ruleType) ?? ""}
        value={identifier}
        onChange={(e) => { setIdentifier(e.target.value); }}
        disabled={busy}
        autoFocus
      />

      <Select
        id="rule-severity"
        label="Severity"
        inline={false}
        value={severity}
        onChange={(e) => { setSeverity(e.target.value); }}
        disabled={busy}
      >
        {SEVERITIES.map((s) => (
          <option key={s} value={s}>{s}</option>
        ))}
      </Select>

      <Input
        id="rule-custom-msg"
        label="Custom message (optional)"
        type="text"
        placeholder="Blocked by corporate policy"
        value={customMsg}
        onChange={(e) => { setCustomMsg(e.target.value); }}
        disabled={busy}
      />

      <Input
        id="rule-custom-url"
        label="More info URL (optional, http/https only)"
        type="url"
        placeholder="https://help.example.com/blocked"
        value={customURL}
        onChange={(e) => { setCustomURL(e.target.value); }}
        disabled={busy}
      />

      <Input
        id="rule-reason"
        label="Reason (required for audit log)"
        type="text"
        placeholder="Why are you authoring this rule?"
        value={reason}
        onChange={(e) => { setReason(e.target.value); }}
        disabled={busy}
      />
    </AppControlDialogShell>
  );
}
