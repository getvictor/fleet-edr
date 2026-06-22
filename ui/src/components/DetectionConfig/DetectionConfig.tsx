import { useCallback, useEffect, useRef, useState } from "react";
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

// The three per-rule modes (api.DetectionRuleMode): alert (default), monitor (evaluate but
// emit a signal instead of an alert), disabled (emit nothing).
const MODES = ["alert", "monitor", "disabled"] as const;

// Severity-override choices; the empty value means "no override" (keep the rule's declared severity).
const SEVERITIES = ["", "low", "medium", "high", "critical"] as const;

// errMessage renders a typed detection-config API error's message, falling back to a generic string.
function errMessage(err: unknown): string {
  if (err instanceof DetectionConfigApiError) return err.message;
  return err instanceof Error ? err.message : "Unknown error";
}

// globalSetting picks the global-scope (host_group_id 0) setting for a rule, the only scope the Phase A surface edits.
function globalSetting(settings: DetectionRuleSetting[], ruleID: string): DetectionRuleSetting | undefined {
  return settings.find((s) => s.rule_id === ruleID && s.host_group_id === 0);
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

  // Add-exclusion form state.
  const [formRuleID, setFormRuleID] = useState("");
  const [formMatchType, setFormMatchType] = useState<string>(MATCH_TYPES[0]);
  const [formValue, setFormValue] = useState("");
  const [formReason, setFormReason] = useState("");

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
      });
      setFormValue("");
      setFormReason("");
    }).catch(() => { /* surfaced via actionError */ });
  }, [runMutation, formRuleID, formMatchType, formValue, formReason]);

  const handleDelete = useCallback((id: number) => {
    runMutation(() => deleteDetectionExclusion(id, "removed via admin UI"))
      .catch(() => { /* surfaced via actionError */ });
  }, [runMutation]);

  const handleSettingChange = useCallback((ruleID: string, mode: string, severity: string) => {
    runMutation(() => upsertDetectionRuleSetting({
      rule_id: ruleID,
      mode,
      severity_override: severity || undefined,
      reason: "updated via admin UI",
    })).catch(() => { /* surfaced via actionError */ });
  }, [runMutation]);

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
                <Select label="Rule" id="dc-rule" value={formRuleID} onChange={(e) => { setFormRuleID(e.target.value); }}>
                  <option value="">Select a rule...</option>
                  {rules.map((r) => <option key={r.id} value={r.id}>{r.doc.title} ({r.id})</option>)}
                </Select>
                <Select label="Match type" id="dc-match" value={formMatchType} onChange={(e) => { setFormMatchType(e.target.value); }}>
                  {MATCH_TYPES.map((m) => <option key={m} value={m}>{m}</option>)}
                </Select>
                <Input label="Value" id="dc-value" value={formValue} onChange={(e) => { setFormValue(e.target.value); }}
                  placeholder="*/claude/versions/*" />
                <Input label="Reason" id="dc-reason" value={formReason} onChange={(e) => { setFormReason(e.target.value); }}
                  placeholder="why this is benign" />
                <Button variant="primary" disabled={addDisabled || mutating} onClick={handleAddExclusion}>Add exclusion</Button>
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
                      <td>{ex.created_by}</td>
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
                  <th>Mode</th>
                  <th>Severity override</th>
                </tr>
              </thead>
              <tbody>
                {rules.map((r) => {
                  const setting = globalSetting(settings, r.id);
                  const mode = setting?.mode ?? "alert";
                  const severity = setting?.severity_override ?? "";
                  return (
                    <tr key={r.id}>
                      <td>{r.doc.title}<br /><code className="detection-config__rule-id">{r.id}</code></td>
                      <td>
                        <Select label="" id={`dc-mode-${r.id}`} value={mode} disabled={!canWrite || mutating}
                          aria-label={`mode for ${r.id}`}
                          onChange={(e) => { handleSettingChange(r.id, e.target.value, severity); }}>
                          {MODES.map((m) => <option key={m} value={m}>{m}</option>)}
                        </Select>
                      </td>
                      <td>
                        <Select label="" id={`dc-sev-${r.id}`} value={severity} disabled={!canWrite || mutating}
                          aria-label={`severity override for ${r.id}`}
                          onChange={(e) => { handleSettingChange(r.id, mode, e.target.value); }}>
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
    </>
  );
}
