import { useCallback, useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router";
import {
  checkRuleContentDocument,
  getRuleContentDocument,
  listRuleContentDocuments,
  putRuleContentDocument,
  ReauthRequiredError,
  RuleContentApiError,
  ruleDocumentStem,
  type RuleContentCheckResult,
} from "../api";
import { useReauthRetry } from "../hooks/useReauthRetry";
import { ReasonModal } from "./DetectionConfig/ReasonModal";
import { ReauthModal } from "./ReauthModal";
import { Button } from "./ui/Button";
import { Input } from "./ui/Input";
import { EmptyState } from "./ui/Table";
import { PageHeader } from "./ui/PageHeader";
import "./RuleEditor.scss";

// The directory a new rule's document is stored under. A rule's identity is its file stem, not its path, so the directory is a filing
// choice rather than a meaning; this one keeps a deployment's own rules together.
const authoredDirectory = "authored";

// The characters a rule identifier may use (docs/rules/README.md). Checked here only to say so before the round trip; the server's
// loader is the authority and refuses anything else with its own reason.
const identifierPattern = /^[A-Za-z0-9_-]{1,255}$/;

// A new rule starts from the smallest document the loader accepts, so the operator edits a rule rather than recalling the format.
const newRuleTemplate = `title: My rule
status: experimental
description: What this rule detects.
logsource:
    category: process_creation
    product: macos
detection:
    selection:
        Image: '/usr/bin/example'
    condition: selection
level: medium
`;

type LoadState = { kind: "loading" } | { kind: "ready"; path: string } | { kind: "missing" } | { kind: "error"; message: string };

// RuleEditor creates or edits one rule document (issue #1001). The API behind it is built, permissioned, and audited; this is the page
// that makes it reachable without curl.
//
// Check before save is the loop the page is built around: the server's dry run answers with the loader's own verdict, so what the
// operator sees is exactly whether this deployment would load the rule, with no second rule engine in the browser to disagree with it.
export function RuleEditor() {
  const { ruleId } = useParams<{ ruleId: string }>();
  const isNew = ruleId === undefined;
  const navigate = useNavigate();

  const [identifier, setIdentifier] = useState("");
  const [content, setContent] = useState(isNew ? newRuleTemplate : "");
  const [load, setLoad] = useState<LoadState>(isNew ? { kind: "ready", path: "" } : { kind: "loading" });
  const [check, setCheck] = useState<RuleContentCheckResult | null>(null);
  const [checking, setChecking] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [reasonOpen, setReasonOpen] = useState(false);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (isNew) return undefined;
    let cancelled = false;
    (async () => {
      const documents = await listRuleContentDocuments();
      const match = documents.find((d) => ruleDocumentStem(d.path) === ruleId);
      if (match === undefined) return { kind: "missing" } as const;
      const text = await getRuleContentDocument(match.path);
      return { kind: "ready", path: match.path, text } as const;
    })()
      .then((next) => {
        if (cancelled) return;
        if (next.kind === "ready") {
          setContent(next.text);
          setLoad({ kind: "ready", path: next.path });
        } else {
          setLoad(next);
        }
      })
      .catch((err: unknown) => {
        if (!cancelled) setLoad({ kind: "error", message: err instanceof Error ? err.message : "Unknown error" });
      });
    return () => { cancelled = true; };
  }, [isNew, ruleId]);

  const path = isNew ? `${authoredDirectory}/${identifier}.yml` : load.kind === "ready" ? load.path : "";
  const identifierValid = !isNew || identifierPattern.test(identifier);

  // Any edit invalidates the last check: a verdict about different content must not sit beside this content looking current.
  const onContentChange = (next: string) => {
    setContent(next);
    setCheck(null);
    setSaveError(null);
  };

  const runCheck = () => {
    setChecking(true);
    setSaveError(null);
    checkRuleContentDocument(path, content)
      .then(setCheck)
      .catch((err: unknown) => { setSaveError(err instanceof Error ? err.message : "The check could not be run"); })
      .finally(() => { setChecking(false); });
  };

  const save = useCallback(async (reason: string) => putRuleContentDocument(path, content, reason), [path, content]);
  const { call: callSave, modal: reauthModal } = useReauthRetry(save);

  const onConfirmSave = (reason: string) => {
    setSaving(true);
    callSave(reason)
      .then(() => {
        const stem = ruleDocumentStem(path);
        void navigate(`/rules/${encodeURIComponent(stem)}`, { state: { saved: isNew ? "created" : "updated" } });
      })
      .catch((err: unknown) => {
        setReasonOpen(false);
        if (err instanceof ReauthRequiredError) return;
        setSaveError(saveErrorMessage(err));
      })
      .finally(() => { setSaving(false); });
  };

  if (load.kind === "loading") return <EmptyState>Loading the rule document...</EmptyState>;
  if (load.kind === "error") return <EmptyState>The rule document could not be loaded: {load.message}</EmptyState>;
  if (load.kind === "missing") {
    return (
      <EmptyState>
        Rule <code>{ruleId}</code> has no stored document to edit. <Link to="/rules">Back to rules</Link>.
      </EmptyState>
    );
  }

  return (
    <>
      <PageHeader title={isNew ? "New rule" : "Edit rule"} subtitle={isNew ? undefined : <code>{ruleId}</code>} />
      <div className="rule-editor">
        {isNew && (
          <>
            {/* Stated at the point of creation, because a rule that alerts nothing looks broken to someone not told why. */}
            <p className="rule-editor__notice">
              A new rule runs in <strong>monitor</strong> mode: it records what it matches and raises no alert until you promote it
              in <Link to="/detection-config">Detection tuning</Link>.
            </p>
            <Input
              id="rule-editor-identifier"
              label="Identifier"
              value={identifier}
              placeholder="my_rule"
              onChange={(e) => { setIdentifier(e.target.value); setCheck(null); }}
            />
            <p className="rule-editor__hint">
              Letters, digits, underscore, and hyphen. It names the rule everywhere, including per-rule settings, and cannot match a
              rule the product ships. Stored as <code>{`${authoredDirectory}/${identifier || "…"}.yml`}</code>.
            </p>
          </>
        )}
        <label htmlFor="rule-editor-content" className="rule-editor__label">Rule document</label>
        <textarea
          id="rule-editor-content"
          className="rule-editor__content"
          spellCheck={false}
          rows={24}
          value={content}
          onChange={(e) => { onContentChange(e.target.value); }}
        />

        {check !== null && check.would_apply && (
          <div className="rule-editor__verdict rule-editor__verdict--ok" role="status">
            This deployment would load this rule.
          </div>
        )}
        {check !== null && !check.would_apply && (
          // The rule's problem, in the loader's own words. It is a verdict about the content, not a failed request.
          <div className="rule-editor__verdict rule-editor__verdict--refused" role="alert">
            This deployment would not load this rule: {check.refusal ?? "no reason given"}
          </div>
        )}
        {check !== null && check.warnings.length > 0 && (
          <ul className="rule-editor__warnings" aria-label="Warnings">
            {check.warnings.map((w) => <li key={w}>{w}</li>)}
          </ul>
        )}
        {saveError !== null && <div className="rule-editor__verdict rule-editor__verdict--refused" role="alert">{saveError}</div>}

        <div className="rule-editor__actions">
          <Link to={isNew ? "/rules" : `/rules/${encodeURIComponent(ruleId)}`}>Cancel</Link>
          <Button variant="inverse" onClick={runCheck} disabled={!identifierValid || checking} isLoading={checking}>
            Check
          </Button>
          {/* Save waits for a passing check of exactly this content, so nothing is written that the dry run has not seen. */}
          <Button onClick={() => { setReasonOpen(true); }} disabled={check?.would_apply !== true || saving}>
            Save
          </Button>
        </div>
      </div>
      {reasonOpen && (
        <ReasonModal
          title={isNew ? "Create rule" : "Save rule"}
          description="Every rule change is recorded in the audit log with its reason."
          confirmLabel={isNew ? "Create" : "Save"}
          placeholder="Why is this rule being changed?"
          busy={saving}
          onConfirm={onConfirmSave}
          onCancel={() => { setReasonOpen(false); }}
        />
      )}
      <ReauthModal {...reauthModal} />
    </>
  );
}

// saveErrorMessage turns a failed write into something the operator can act on. A refusal carries the loader's reason; a conflict means
// the rules changed between the check and the write, which a fresh check resolves.
function saveErrorMessage(err: unknown): string {
  if (err instanceof RuleContentApiError) {
    if (err.code === "rule_content.conflict") {
      return "The rules changed while this was being saved. Check again, then save.";
    }
    return `Not saved: ${err.message}`;
  }
  return err instanceof Error ? `Not saved: ${err.message}` : "Not saved.";
}
