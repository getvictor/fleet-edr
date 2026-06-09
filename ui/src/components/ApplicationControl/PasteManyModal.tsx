import { useCallback, useEffect, useMemo, useState } from "react";
import {
  bulkUpsertAppControlRules,
  MAX_BULK_UPSERT_ITEMS,
  type BulkUpsertAppControlRuleItem,
  type BulkUpsertAppControlRulesRequest,
  type BulkUpsertAppControlResult,
} from "../../api";
import { useReauthRetry } from "../../hooks/useReauthRetry";
import { ReauthModal } from "../ReauthModal";
import { Input, Select } from "../ui/Input";
import { AppControlDialogShell } from "./AppControlDialogShell";
import { applyAppControlSubmitError } from "./dialogErrors";
import {
  PASTE_MANY_RULE_TYPES,
  parsePasteInput,
  type PasteInference,
} from "./pasteInference";
import "./ApplicationControl.scss";

// PasteManyModalProps mirrors the AddRuleModal contract: open drives showModal()/close(); onClose fires on Cancel/Escape;
// onUpserted fires after a successful bulk-upsert so the parent refreshes the policy.
interface PasteManyModalProps {
  readonly open: boolean;
  readonly policyID: number;
  readonly onClose: () => void;
  readonly onUpserted: (result: BulkUpsertAppControlResult) => void;
}

const DIALOG_TITLE_ID = "paste-many-modal-title";
const SEVERITIES = ["low", "medium", "high", "critical"];

// PLACEHOLDER_BINARY_LENGTH is the placeholder SHA-256 length so the textarea hint matches the BINARY rule_type's hex width.
const PLACEHOLDER_BINARY_LENGTH = 64;
const PLACEHOLDER_TEXTAREA = "a".repeat(PLACEHOLDER_BINARY_LENGTH) + "\nEQHXZ8M8AV\nplatform:com.apple.curl";

// AVAILABLE_RULE_TYPES are the same Phase A close-out values AddRuleModal accepts. CERTIFICATE + PATH are inferred from
// shape but flagged as unavailable so the operator overrides them to BINARY (or removes the row) before submit. Keeping
// the gate here in lockstep with AddRuleModal so both UI surfaces agree on what the server validators accept today.
const AVAILABLE_RULE_TYPES = new Set(["BINARY", "CDHASH", "SIGNINGID", "TEAMID"]);

// errorMessageByCode maps server-typed application_control.* codes to operator-friendly copy. `invalid_rule` is intentionally
// absent: the server's per-item message ("bulk item 1: identifier failed validation") names the offending row index, which is
// strictly more useful than any generic UI copy could be, so applyAppControlSubmitError falls through to err.message verbatim
// for that code.
const errorMessageByCode = new Map<string, string>([
  ["application_control.duplicate_rule", "Duplicate identifiers found in the batch."],
  ["application_control.policy_not_found", "The policy was deleted before the batch could be saved."],
  ["application_control.invalid_policy_id", "Invalid policy id."],
  ["application_control.invalid_json", "The request body was not valid JSON."],
]);

// nextRowId is the module-level counter that mints a stable id per parsed row. React keys built from row index would shift
// when a middle row is removed (Gemini finding on PR #192) and force every later row to unmount + remount, dropping any
// in-flight select / focus state along the way. The counter survives across modal opens - collisions don't matter because
// keys only need to be unique within a single React list reconciliation, not globally.
let nextRowId = 0;

// PasteRow is the modal's working copy of a parsed line: identifier + the inferrer's verdict + the operator's override
// (initially equal to the inference). The unavailable flag short-circuits submit so we don't ship a CERTIFICATE/PATH
// row the server will refuse anyway.
interface PasteRow {
  readonly id: number;
  readonly identifier: string;
  readonly raw: string;
  readonly inferredType: string | null;
  readonly hint?: string;
  ruleType: string | null;
}

function rowsFromParse(parsed: PasteInference[]): PasteRow[] {
  return parsed.map((p) => {
    nextRowId += 1;
    return {
      id: nextRowId,
      identifier: p.identifier,
      raw: p.raw,
      inferredType: p.ruleType,
      ruleType: p.ruleType,
      ...(p.hint ? { hint: p.hint } : {}),
    };
  });
}

export function PasteManyModal({ open, policyID, onClose, onUpserted }: PasteManyModalProps) {
  // Two phases: "paste" shows the textarea + Parse button; "preview" shows the per-row table + Save button. The phase
  // transition is one-way: editing a row in preview happens in place. Cancel resets to paste on next open.
  const [phase, setPhase] = useState<"paste" | "preview">("paste");
  const [rawInput, setRawInput] = useState("");
  const [rows, setRows] = useState<PasteRow[]>([]);
  const [severity, setSeverity] = useState("medium");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  // Reset the whole form whenever the dialog opens. Otherwise a Cancel + re-open would surface the prior paste's state.
  useEffect(() => {
    if (!open) return;
    // eslint-disable-next-line react-hooks/set-state-in-effect -- intentional reset tied to the open prop transition
    setPhase("paste");
    setRawInput("");
    setRows([]);
    setSeverity("medium");
    setReason("");
    setBusy(false);
    setFormError(null);
  }, [open]);

  const submitBulk = useCallback(
    (req: BulkUpsertAppControlRulesRequest) => bulkUpsertAppControlRules(policyID, req),
    [policyID],
  );
  const { call: callBulk, modal: reauthModal } = useReauthRetry(submitBulk);

  // unresolvedCount captures rows the operator still needs to address: ruleType=null (no shape matched) or ruleType set to
  // an unavailable type (CERTIFICATE / PATH). Submit is disabled until every row has a server-acceptable type.
  const unresolvedCount = useMemo(
    () => rows.filter((r) => r.ruleType === null || !AVAILABLE_RULE_TYPES.has(r.ruleType)).length,
    [rows],
  );

  const submitDisabled =
    busy || phase !== "preview" || rows.length === 0 || unresolvedCount > 0 || reason.trim().length === 0;

  function handleParse(e: React.SyntheticEvent) {
    e.preventDefault();
    const parsed = parsePasteInput(rawInput);
    if (parsed.length === 0) {
      setFormError("Paste one identifier per line.");
      return;
    }
    if (parsed.length > MAX_BULK_UPSERT_ITEMS) {
      setFormError(`Too many identifiers in one batch (${String(parsed.length)} > ${String(MAX_BULK_UPSERT_ITEMS)}).`);
      return;
    }
    setFormError(null);
    setRows(rowsFromParse(parsed));
    setPhase("preview");
  }

  function handleTypeChange(index: number, nextType: string) {
    setRows((prev) => prev.map((row, i) => (i === index ? { ...row, ruleType: nextType } : row)));
  }

  function handleRemoveRow(index: number) {
    setRows((prev) => prev.filter((_, i) => i !== index));
  }

  function handleBack() {
    setPhase("paste");
    setRows([]);
    setFormError(null);
  }

  async function handleSubmit(e: React.SyntheticEvent) {
    e.preventDefault();
    if (phase === "paste") {
      handleParse(e);
      return;
    }
    if (submitDisabled) return;
    setFormError(null);
    setBusy(true);
    try {
      const items: BulkUpsertAppControlRuleItem[] = rows.map((r) => ({
        rule_type: r.ruleType ?? "",
        identifier: r.identifier,
        severity,
      }));
      const result = await callBulk({ rules: items, reason: reason.trim() });
      onUpserted(result);
    } catch (err) {
      if (applyAppControlSubmitError(err, setFormError, errorMessageByCode, "Failed to save bulk rules.")) {
        return;
      }
    } finally {
      setBusy(false);
    }
  }

  // Pluralisation kept as a separate helper so the subtitle + submitLabel ternaries above don't nest one inside the other
  // (Sonar S3358 - nested ternaries are unreadable). pluralSuffix returns "" or "s" only; the caller composes the noun.
  const pluralSuffix = rows.length === 1 ? "" : "s";
  const previewSubtitle = `${String(rows.length)} row${pluralSuffix} ready. Override any inferred type before saving.`;
  const previewSubmitLabel = `Save ${String(rows.length)} rule${pluralSuffix}`;
  const subtitle = phase === "paste"
    ? "Paste one identifier per line. The next step infers the rule type per line and lets you override it before saving."
    : previewSubtitle;
  const submitLabel = phase === "paste" ? "Parse" : previewSubmitLabel;

  return (
    <AppControlDialogShell
      open={open}
      onClose={onClose}
      titleId={DIALOG_TITLE_ID}
      title="Paste many rules"
      subtitle={subtitle}
      formError={formError}
      busy={busy}
      submitDisabled={phase === "paste" ? rawInput.trim().length === 0 || busy : submitDisabled}
      submitLabel={submitLabel}
      submitBusyLabel="Saving…"
      onSubmit={(e) => { void handleSubmit(e); }}
      reauthModal={<ReauthModal {...reauthModal} />}
    >
      {phase === "paste" && (
        <div className="app-control-dialog__field">
          <label htmlFor="paste-many-input" className="app-control-dialog__label">
            Identifiers (one per line)
          </label>
          <textarea
            id="paste-many-input"
            className="app-control-dialog__textarea"
            rows={10}
            spellCheck={false}
            autoComplete="off"
            placeholder={PLACEHOLDER_TEXTAREA}
            value={rawInput}
            onChange={(e) => { setRawInput(e.target.value); }}
            disabled={busy}
            autoFocus
          />
        </div>
      )}

      {phase === "preview" && (
        <>
          <div className="app-control-dialog__paste-preview">
            <table className="app-control-dialog__paste-table">
              <thead>
                <tr>
                  <th>Identifier</th>
                  <th>Type</th>
                  <th>Notes</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {rows.map((row, index) => {
                  const typeUnavailable = row.ruleType !== null && !AVAILABLE_RULE_TYPES.has(row.ruleType);
                  return (
                    <tr key={row.id}>
                      <td className="app-control__identifier" title={row.identifier}>
                        {row.identifier}
                      </td>
                      <td>
                        <select
                          aria-label={`Type for row ${String(index + 1)}`}
                          value={row.ruleType ?? ""}
                          onChange={(e) => { handleTypeChange(index, e.target.value); }}
                          disabled={busy}
                        >
                          <option value=""> - pick a type - </option>
                          {PASTE_MANY_RULE_TYPES.map((t) => (
                            <option key={t} value={t} disabled={!AVAILABLE_RULE_TYPES.has(t)}>
                              {t}{AVAILABLE_RULE_TYPES.has(t) ? "" : " (coming soon)"}
                            </option>
                          ))}
                        </select>
                      </td>
                      <td className="app-control-dialog__paste-notes">
                        {row.hint && <span>{row.hint}</span>}
                        {row.ruleType === null && <span>No matching shape; pick a type.</span>}
                        {typeUnavailable && <span>Type not enabled in this build.</span>}
                      </td>
                      <td>
                        <button
                          type="button"
                          className="app-control-dialog__paste-remove"
                          onClick={() => { handleRemoveRow(index); }}
                          disabled={busy}
                          aria-label={`Remove row ${String(index + 1)}`}
                        >
                          ×
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          <Select
            id="paste-many-severity"
            label="Severity (applied to every row)"
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
            id="paste-many-reason"
            label="Reason (required for audit log)"
            type="text"
            placeholder="Why are you importing these rules?"
            value={reason}
            onChange={(e) => { setReason(e.target.value); }}
            disabled={busy}
          />

          <button
            type="button"
            className="app-control-dialog__paste-back"
            onClick={handleBack}
            disabled={busy}
          >
            ← Back to paste
          </button>
        </>
      )}
    </AppControlDialogShell>
  );
}
