import { useCallback, useEffect, useRef, useState } from "react";
import { Link, useNavigate, useParams } from "react-router";
import {
  checkRuleContentDocument,
  fetchRuleDocs,
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
import { isLocallyAuthored } from "./ruleOrigin";
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

type LoadState =
  | { kind: "loading" }
  | { kind: "ready"; path: string }
  | { kind: "missing" }
  | { kind: "built-in" }
  | { kind: "error"; message: string };

// RuleEditor creates or edits one rule document (issue #1001). The API behind it is built, permissioned, and audited; this is the page
// that makes it reachable without curl.
//
// Check before save is the loop the page is built around: the server's dry run answers with the loader's own verdict on the document,
// with no second rule engine in the browser to disagree with it. The dry run judges the document alone. Whether it fits beside the
// deployment's other rules, an identifier a built-in rule already uses for instance, is decided when it is saved, and a refusal then is
// shown in the loader's words too.
export function RuleEditor() {
  const { ruleId } = useParams<{ ruleId: string }>();
  // Keyed by the rule so moving to another rule's editor, which keeps this route mounted, starts from a fresh draft: a check or a
  // loaded document belongs to the rule it was made for.
  return <RuleEditorPage key={ruleId ?? ""} ruleId={ruleId} />;
}

function RuleEditorPage({ ruleId }: { readonly ruleId: string | undefined }) {
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
  // draft counts edits to what a check is about. A check answers for the draft it was started on, so a response that arrives after a
  // further edit is discarded rather than arming Save for content the server never saw.
  const draft = useRef(0);

  useEffect(() => {
    if (isNew) return undefined;
    let cancelled = false;
    (async () => {
      const [rules, documents] = await Promise.all([fetchRuleDocs(), listRuleContentDocuments()]);
      // Origin first: a built-in rule that came with the product has no stored document, and is still one to tune rather than edit.
      if (isBuiltIn(rules.find((r) => r.id === ruleId)?.origin)) return { kind: "built-in" } as const;
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
  const leaveTo = isNew ? "/rules" : `/rules/${encodeURIComponent(ruleId)}`;
  const identifierValid = !isNew || identifierPattern.test(identifier);

  // Any edit invalidates the last check: a verdict about different content must not sit beside this content looking current.
  const invalidateCheck = () => {
    draft.current += 1;
    setCheck(null);
    setSaveError(null);
  };
  const onContentChange = (next: string) => {
    setContent(next);
    invalidateCheck();
  };

  const runCheck = () => {
    const checked = draft.current;
    setChecking(true);
    setSaveError(null);
    checkRuleContentDocument(path, content)
      .then((result) => {
        if (draft.current === checked) setCheck(result);
      })
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
        // A conflict says to check again, so the passing check it invalidated must not leave Save available.
        if (err instanceof RuleContentApiError && err.code === conflictCode) setCheck(null);
        setSaveError(saveErrorMessage(err));
      })
      .finally(() => { setSaving(false); });
  };

  if (load.kind === "loading") return <EmptyState>Loading the rule document...</EmptyState>;
  if (load.kind === "error") return <EmptyState>The rule document could not be loaded: {load.message}</EmptyState>;
  if (load.kind === "built-in") {
    return (
      <EmptyState>
        <code>{ruleId}</code> is built in, so it is tuned in <Link to="/detection-config">Detection tuning</Link> rather than
        edited here. <Link to={leaveTo}>Back to the rule</Link>.
      </EmptyState>
    );
  }
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
              onChange={(e) => { setIdentifier(e.target.value); invalidateCheck(); }}
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
            The document is valid. Saving also checks it against the deployment&apos;s other rules.
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
          <Link to={leaveTo}>Cancel</Link>
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

// conflictCode is the API's error code for a write that lost a race with another change to the rules.
const conflictCode = "rule_content.conflict";

// isBuiltIn reports whether the server credits a rule to someone other than this deployment. Such a rule is tuned in Detection tuning
// rather than edited here, since the next install of built-in content would meet an edit made to it. The Edit link already follows
// that, and this holds it for an address typed directly.
//
// Only a known origin says so. A rule the server does not report (one the loader refused, or one written moments ago and not yet
// loaded) or reports without an origin (an older replica) is left editable: the permission to write its document is the same either
// way, and the server is the authority on what it accepts.
function isBuiltIn(origin: string | undefined): boolean {
  return origin !== undefined && !isLocallyAuthored(origin);
}

// saveErrorMessage turns a failed write into something the operator can act on. A refusal carries the loader's reason; a conflict means
// the rules changed between the check and the write, which a fresh check resolves.
function saveErrorMessage(err: unknown): string {
  if (err instanceof RuleContentApiError) {
    if (err.code === conflictCode) {
      return "The rules changed while this was being saved. Check again, then save.";
    }
    return `Not saved: ${err.message}`;
  }
  return err instanceof Error ? `Not saved: ${err.message}` : "Not saved.";
}
