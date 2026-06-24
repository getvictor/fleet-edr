import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  listDetectionExclusions,
  listDetectionRuleSettings,
  createDetectionExclusion,
  deleteDetectionExclusion,
  upsertDetectionRuleSetting,
  fetchRuleDocs,
  DetectionConfigApiError,
  type DetectionExclusion,
  type DetectionRuleSetting,
  type RuleDocEntry,
} from "../../api";
import { useCan, PermissionAction } from "../../permissions-core";
import { PageHeader } from "../ui/PageHeader";
import { Table, EmptyState } from "../ui/Table";
import { Button } from "../ui/Button";
import { Input, Select } from "../ui/Input";
import { ReasonModal } from "./ReasonModal";
import "./DetectionConfig.scss";

// The match types the exclusion editor offers, mirroring api.ExclusionMatchType server-side.
const MATCH_TYPES = [
  "path_glob",
  "parent_path_glob",
  "team_id",
  "signing_id",
  "cdhash",
  "sha256",
  "command_substring",
  "domain",
] as const;

// The per-rule modes an operator can select: alert (default) and disabled (emit nothing). A legacy `monitor` value may still exist on
// persisted rows and the engine continues to honor it, but monitor is no longer operator-selectable (it had no review surface). See
// the detection-tuning-author-and-modes openspec change.
const MODES = ["alert", "disabled"] as const;

// modeOptions returns the modes shown for a row. It prepends the row's current mode when that mode is not operator-selectable (a
// legacy `monitor` row) so the controlled <select> renders a matching option and the operator can migrate it to alert/disabled.
function modeOptions(current: string): readonly string[] {
  return (MODES as readonly string[]).includes(current) ? MODES : [current, ...MODES];
}

// Severity-override choices; the empty value means "no override" (keep the rule's declared severity).
const SEVERITIES = ["", "low", "medium", "high", "critical"] as const;

// SEVERITY_ORDER lists declared severities most- to least-severe; the rule-modes table sorts by it (ascending rank = critical first).
const SEVERITY_ORDER = ["critical", "high", "medium", "low"] as const;

// severityRank returns a rule's position in SEVERITY_ORDER (0 = critical). A severity that isn't one of the four (an unset "" or an
// unrecognized value) ranks last, so "(unspecified)" rules fall to the bottom of the table.
function severityRank(sev: string): number {
  const i = SEVERITY_ORDER.indexOf(sev as (typeof SEVERITY_ORDER)[number]);
  return i === -1 ? SEVERITY_ORDER.length : i;
}

// errMessage renders a typed detection-config API error's message, falling back to a generic string.
function errMessage(err: unknown): string {
  if (err instanceof DetectionConfigApiError) return err.message;
  return err instanceof Error ? err.message : "Unknown error";
}

// globalSetting picks the global-scope (host_group_id 0) setting for a rule, the only scope the Phase A surface edits.
function globalSetting(settings: DetectionRuleSetting[], ruleID: string): DetectionRuleSetting | undefined {
  return settings.find((s) => s.rule_id === ruleID && s.host_group_id === 0);
}

// ruleLabel is the concise rule name the picker shows. Catalog titles carry a trailing descriptive aside (e.g. "Suspicious exec
// chain (non-shell → shell → temp/network)") which, paired with the rule id, made each option long and noisy. Top EDR consoles list
// the short rule name only, so we drop the aside and the id; the id still rides as the option value.
function ruleLabel(title: string): string {
  // Drop a trailing " (...)" aside with linear string ops rather than a regex: the equivalent /\s*\([^)]*\)\s*$/ has super-linear
  // backtracking (Sonar S8786) because .replace retries the greedy leading \s* at every start position.
  const trimmed = title.trimEnd();
  if (trimmed.endsWith(")")) {
    const open = trimmed.lastIndexOf("(");
    if (open > 0) return trimmed.slice(0, open).trim() || title;
  }
  return title;
}

// DetectionConfig is the admin surface for detection-rule tuning (issue #459): per-host false-positive exclusions and per-rule
// mode/severity. It edits global scope only (host-group scoping arrives with editable host groups). Write affordances are gated on
// detection_config.write; the server still enforces. The per-rule "settings" are mode + severity today; when a rule declares
// additional config the table grows generically.
export function DetectionConfig() {
  const can = useCan();
  const canWrite = can(PermissionAction.DetectionConfigWrite);

  const [exclusions, setExclusions] = useState<DetectionExclusion[]>([]);
  const [rules, setRules] = useState<RuleDocEntry[]>([]);
  const [settings, setSettings] = useState<DetectionRuleSetting[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  // mutating serializes write actions: while a create/delete/upsert is in flight (and its reload settles) the form controls and
  // row buttons disable, so a double-click can't double-submit and a second rule-mode change can't race a stale peer field in.
  const [mutating, setMutating] = useState(false);
  // mountedRef gates the state setters in reload() so a response landing after unmount doesn't set state on a dead component.
  const mountedRef = useRef(true);
  useEffect(() => () => { mountedRef.current = false; }, []);

  // Add-exclusion form state. formExpires is an optional YYYY-MM-DD from a date input; converted to an RFC3339 end-of-day instant.
  const [formRuleID, setFormRuleID] = useState("");
  const [formMatchType, setFormMatchType] = useState<string>(MATCH_TYPES[0]);
  const [formValue, setFormValue] = useState("");
  const [formReason, setFormReason] = useState("");
  const [formExpires, setFormExpires] = useState("");

  // pendingMode holds a not-yet-applied disable (the alerting-reducing change) while the reason modal collects an operator
  // justification. modalError surfaces a failed confirm inside the modal so it stays open for a retry.
  const [pendingMode, setPendingMode] = useState<{ ruleID: string; ruleTitle: string; mode: string; severity: string } | null>(null);
  const [modalError, setModalError] = useState<string | null>(null);

  // The exclusion picker lists rules alphabetically by display name so an operator can scan to the rule they want.
  const rulesByName = useMemo(
    () => [...rules].sort((a, b) => ruleLabel(a.doc.title).localeCompare(ruleLabel(b.doc.title))),
    [rules],
  );
  // The rule-modes table orders by declared severity (critical first), where muting a rule is most consequential, then
  // alphabetically by title within a severity band.
  const rulesBySeverity = useMemo(
    () => [...rules].sort((a, b) =>
      severityRank(a.doc.severity) - severityRank(b.doc.severity) || a.doc.title.localeCompare(b.doc.title)),
    [rules],
  );

  const reload = useCallback(async (): Promise<void> => {
    const [excl, ruleDocs, ruleSettings] = await Promise.all([
      listDetectionExclusions(),
      fetchRuleDocs(),
      listDetectionRuleSettings(),
    ]);
    if (!mountedRef.current) return;
    setExclusions(excl);
    setRules(ruleDocs);
    setSettings(ruleSettings);
  }, []);

  useEffect(() => {
    let cancelled = false;
    setLoading(true); // eslint-disable-line react-hooks/set-state-in-effect -- data fetch pattern
    setError(null);
    reload()
      .catch((err: unknown) => {
        if (!cancelled) setError(errMessage(err));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => { cancelled = true; };
  }, [reload]);

  const runMutation = useCallback(async (op: () => Promise<unknown>): Promise<void> => {
    setActionError(null);
    setMutating(true);
    try {
      await op();
      await reload();
    } catch (err: unknown) {
      setActionError(errMessage(err));
    } finally {
      if (mountedRef.current) setMutating(false);
    }
  }, [reload]);

  const handleAddExclusion = useCallback(() => {
    // Trim before sending: the UI validates on trimmed input, so persisting the raw string would let stray
    // leading/trailing whitespace into glob/substring matches and the audit reason. runMutation never rejects
    // (it captures errors into actionError), so the trailing catch is a belt-and-braces no-op for the linters.
    runMutation(async () => {
      await createDetectionExclusion({
        rule_id: formRuleID,
        match_type: formMatchType,
        value: formValue.trim(),
        reason: formReason.trim(),
        // A date input yields YYYY-MM-DD; treat it as "valid through the end of that UTC day" so the exclusion covers the whole day.
        expires_at: formExpires ? `${formExpires}T23:59:59Z` : undefined,
      });
      setFormValue("");
      setFormReason("");
      setFormExpires("");
    }).catch(() => { /* surfaced via actionError */ });
  }, [runMutation, formRuleID, formMatchType, formValue, formReason, formExpires]);

  const handleDelete = useCallback((id: number) => {
    // Deleting an exclusion restores detection coverage (a coverage-increasing action), so it carries a generated reason rather
    // than prompting; the audit row still records the actor, target, and timestamp.
    runMutation(() => deleteDetectionExclusion(id, "removed via admin UI"))
      .catch(() => { /* surfaced via actionError */ });
  }, [runMutation]);

  // handleModeChange splits on whether the new mode reduces alerting. Restoring a rule to `alert` is applied immediately with a
  // generated reason; disabling it first opens the reason modal so the operator's justification is audited.
  const handleModeChange = useCallback((ruleID: string, ruleTitle: string, mode: string, severity: string) => {
    if (mode === "alert") {
      runMutation(() => upsertDetectionRuleSetting({
        rule_id: ruleID, mode, severity_override: severity || undefined, reason: "re-enabled via admin UI",
      })).catch(() => { /* surfaced via actionError */ });
      return;
    }
    setModalError(null);
    setPendingMode({ ruleID, ruleTitle, mode, severity });
  }, [runMutation]);

  // handleSeverityChange tweaks only the severity override (the rule's alerting on/off is unchanged), so it applies immediately
  // with a generated reason.
  const handleSeverityChange = useCallback((ruleID: string, mode: string, severity: string) => {
    runMutation(() => upsertDetectionRuleSetting({
      rule_id: ruleID, mode, severity_override: severity || undefined, reason: "severity override changed via admin UI",
    })).catch(() => { /* surfaced via actionError */ });
  }, [runMutation]);

  // confirmPendingMode applies the pending reducing change with the operator's reason. It keeps its own try/catch (rather than
  // reusing runMutation) so a failure surfaces inside the still-open modal instead of the page-level banner.
  const confirmPendingMode = useCallback((reason: string) => {
    const pending = pendingMode;
    if (!pending) return;
    setModalError(null);
    setMutating(true);
    (async () => {
      try {
        await upsertDetectionRuleSetting({
          rule_id: pending.ruleID, mode: pending.mode, severity_override: pending.severity || undefined, reason,
        });
        await reload();
        if (mountedRef.current) setPendingMode(null);
      } catch (err: unknown) {
        if (mountedRef.current) setModalError(errMessage(err));
      } finally {
        if (mountedRef.current) setMutating(false);
      }
    })().catch(() => { /* inner try/catch handles all paths */ });
  }, [pendingMode, reload]);

  const cancelPendingMode = useCallback(() => {
    setPendingMode(null);
    setModalError(null);
  }, []);

  const addDisabled = !formRuleID || !formValue.trim() || !formReason.trim();

  return (
    <>
      <PageHeader
        title="Detection tuning"
        subtitle="False-positive exclusions and per-rule mode the detection engine consults at evaluation time"
      />
      {loading && <EmptyState>Loading detection configuration...</EmptyState>}
      {error && !loading && <EmptyState>Error: {error}</EmptyState>}
      {actionError && <div className="detection-config__error" role="alert">{actionError}</div>}

      {!loading && !error && (
        <>
          <section className="detection-config__section">
            <h2 className="detection-config__heading">Exclusions</h2>
            {canWrite && (
              <div className="detection-config__form">
                <Select label="Rule" id="dc-rule" inline={false} value={formRuleID}
                  onChange={(e) => { setFormRuleID(e.target.value); }}>
                  <option value="">Select a rule...</option>
                  {rulesByName.map((r) => <option key={r.id} value={r.id}>{ruleLabel(r.doc.title)}</option>)}
                </Select>
                <Select label="Match type" id="dc-match" inline={false} value={formMatchType}
                  onChange={(e) => { setFormMatchType(e.target.value); }}>
                  {MATCH_TYPES.map((m) => <option key={m} value={m}>{m}</option>)}
                </Select>
                <div className="detection-config__form-field--full">
                  <Input label="Value" id="dc-value" value={formValue} onChange={(e) => { setFormValue(e.target.value); }}
                    placeholder="*/MyApp/versions/*" />
                </div>
                <div className="detection-config__form-field--full">
                  <Input label="Reason" id="dc-reason" value={formReason} onChange={(e) => { setFormReason(e.target.value); }}
                    placeholder="why this is benign" />
                </div>
                <Input label="Expires (optional)" id="dc-expires" type="date" value={formExpires}
                  onChange={(e) => { setFormExpires(e.target.value); }} />
                <div className="detection-config__form-actions">
                  <Button variant="primary" disabled={addDisabled || mutating} onClick={handleAddExclusion}>Add exclusion</Button>
                </div>
              </div>
            )}
            {exclusions.length === 0 ? (
              <EmptyState>No exclusions configured.</EmptyState>
            ) : (
              <Table>
                <thead>
                  <tr>
                    <th>Rule</th>
                    <th>Match type</th>
                    <th>Value</th>
                    <th>Reason</th>
                    <th>Expires</th>
                    <th>Created by</th>
                    {canWrite && <th aria-label="actions" />}
                  </tr>
                </thead>
                <tbody>
                  {exclusions.map((ex) => (
                    <tr key={ex.id}>
                      <td>{ex.rule_id || "(shared)"}</td>
                      <td>{ex.match_type}</td>
                      <td><code>{ex.value}</code></td>
                      <td>{ex.reason}</td>
                      <td>{ex.expires_at ? ex.expires_at.split("T")[0] : "never"}</td>
                      <td>{ex.created_by_email || ex.created_by}</td>
                      {canWrite && (
                        <td>
                          <Button variant="alert" disabled={mutating} onClick={() => { handleDelete(ex.id); }}
                            title="Delete this exclusion">Delete</Button>
                        </td>
                      )}
                    </tr>
                  ))}
                </tbody>
              </Table>
            )}
          </section>

          <section className="detection-config__section">
            <h2 className="detection-config__heading">Rule modes</h2>
            <Table>
              <thead>
                <tr>
                  <th>Rule</th>
                  <th title="The severity each rule declares in the catalog. It applies whenever no override is set below.">
                    Default severity
                  </th>
                  <th title="Alert (default) raises alerts; monitor evaluates but emits a signal instead; disabled emits nothing.">
                    Mode
                  </th>
                  <th title="Replaces the rule's default severity on every alert it raises. (none) keeps the default.">
                    Severity override
                  </th>
                </tr>
              </thead>
              <tbody>
                {rulesBySeverity.map((r) => {
                  const setting = globalSetting(settings, r.id);
                  const mode = setting?.mode ?? "alert";
                  const severity = setting?.severity_override ?? "";
                  return (
                    <tr key={r.id}>
                      <td>{r.doc.title}<br /><code className="detection-config__rule-id">{r.id}</code></td>
                      <td className="detection-config__default-severity">{r.doc.severity || "(unspecified)"}</td>
                      <td>
                        <Select label="" id={`dc-mode-${r.id}`} value={mode} disabled={!canWrite || mutating}
                          aria-label={`mode for ${r.id}`}
                          onChange={(e) => { handleModeChange(r.id, r.doc.title, e.target.value, severity); }}>
                          {modeOptions(mode).map((m) => <option key={m} value={m}>{m}</option>)}
                        </Select>
                      </td>
                      <td>
                        <Select label="" id={`dc-sev-${r.id}`} value={severity} disabled={!canWrite || mutating}
                          aria-label={`severity override for ${r.id}`}
                          onChange={(e) => { handleSeverityChange(r.id, mode, e.target.value); }}>
                          {SEVERITIES.map((s) => <option key={s || "none"} value={s}>{s || "(none)"}</option>)}
                        </Select>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </Table>
          </section>
        </>
      )}

      {pendingMode && (
        <ReasonModal
          title={`Disable "${pendingMode.ruleTitle}"?`}
          description="The rule stays registered but stops producing alerts. This is recorded in the audit log."
          confirmLabel="Disable rule"
          confirmVariant="alert"
          busy={mutating}
          error={modalError}
          onConfirm={confirmPendingMode}
          onCancel={cancelPendingMode}
        />
      )}
    </>
  );
}
