import { useCallback, useEffect, useState } from "react";
import { Link, useNavigate } from "react-router";
import {
  deleteRuleContentDocument,
  getRuleContentDocument,
  listRuleContentDocuments,
  ReauthRequiredError,
  ruleDocumentStem,
} from "../api";
import { useReauthRetry } from "../hooks/useReauthRetry";
import { ReasonModal } from "./DetectionConfig/ReasonModal";
import { ReauthModal } from "./ReauthModal";
import { Button } from "./ui/Button";
import "./RuleSource.scss";

type SourceState =
  | { kind: "loading" }
  | { kind: "document"; path: string; content: string }
  | { kind: "builtin" }
  | { kind: "error"; message: string };

const deleteDescription =
  "The rule stops being evaluated when the server next reloads its rules, within 30 seconds. Alerts it already raised are kept.";

// RuleSource shows the file a rule is loaded from, as written (issue #1001). Rules loaded from the stored corpus are Sigma YAML with an
// x-engine block, and reading one as written is how an operator sees exactly what it matches. A rule built into the server is not loaded
// from that corpus, and says so rather than showing an empty panel.
//
// The owning page renders this only for an operator with rule_content.read, since both reads here are gated on it. `editable` adds Edit
// and Delete, which the owning page grants only for a rule this deployment wrote and an operator with rule_content.write: shipped rules
// are tuned in Detection tuning rather than rewritten here, where the next install of shipped content would meet the edit.
export function RuleSource({ ruleId, editable = false }: { readonly ruleId: string; readonly editable?: boolean }) {
  const [state, setState] = useState<SourceState>({ kind: "loading" });
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const navigate = useNavigate();
  const documentPath = state.kind === "document" ? state.path : "";
  const remove = useCallback(async (reason: string) => deleteRuleContentDocument(documentPath, reason), [documentPath]);
  const { call: callDelete, modal: reauthModal } = useReauthRetry(remove);

  const onConfirmDelete = (reason: string) => {
    setDeleting(true);
    setDeleteError(null);
    callDelete(reason)
      .then(() => { void navigate("/rules", { state: { deleted: ruleId } }); })
      .catch((err: unknown) => {
        if (err instanceof ReauthRequiredError) {
          setDeleteOpen(false);
          return;
        }
        // Kept in the modal, beside the action that failed, so the reason just typed is not lost.
        setDeleteError(err instanceof Error ? `Not deleted: ${err.message}` : "Not deleted.");
      })
      .finally(() => { setDeleting(false); });
  };

  useEffect(() => {
    let cancelled = false;
    setState({ kind: "loading" }); // eslint-disable-line react-hooks/set-state-in-effect -- data fetch pattern
    (async () => {
      const documents = await listRuleContentDocuments();
      // A rule's identity is its document's file stem, so the matching document is the one whose stem is the rule id.
      const match = documents.find((d) => ruleDocumentStem(d.path) === ruleId);
      if (match === undefined) return { kind: "builtin" } as const;
      const content = await getRuleContentDocument(match.path);
      return { kind: "document", path: match.path, content } as const;
    })()
      .then((next) => {
        if (!cancelled) setState(next);
      })
      .catch((err: unknown) => {
        if (!cancelled) setState({ kind: "error", message: err instanceof Error ? err.message : "Unknown error" });
      });
    return () => { cancelled = true; };
  }, [ruleId]);

  return (
    <section className="rule-source" aria-labelledby="rule-source-heading">
      {/* Not "Source": the page already uses that word for who wrote the rule. */}
      <h2 id="rule-source-heading" className="rule-source__heading">Rule document</h2>
      {state.kind === "loading" && <p className="rule-source__note">Loading the rule document...</p>}
      {state.kind === "error" && <p className="rule-source__note">The rule document could not be loaded: {state.message}</p>}
      {state.kind === "builtin" && (
        <p className="rule-source__note">
          This rule is built into the server rather than loaded from the stored rule corpus, so there is no stored document to show.
        </p>
      )}
      {state.kind === "document" && (
        <>
          <p className="rule-source__note">
            <code>{state.path}</code>
          </p>
          {editable && (
            <div className="rule-source__actions">
              <Link className="button button--inverse button--small" to={`/rules/${encodeURIComponent(ruleId)}/edit`}>
                Edit
              </Link>
              <Button size="small" variant="alert" onClick={() => { setDeleteError(null); setDeleteOpen(true); }}>
                Delete
              </Button>
            </div>
          )}
          <pre className="rule-source__content">{state.content}</pre>
        </>
      )}
      {deleteOpen && (
        <ReasonModal
          title={`Delete ${ruleId}`}
          description={deleteDescription}
          confirmLabel="Delete"
          confirmVariant="alert"
          placeholder="Why is this rule being deleted?"
          busy={deleting}
          error={deleteError}
          onConfirm={onConfirmDelete}
          onCancel={() => { setDeleteOpen(false); }}
        />
      )}
      <ReauthModal {...reauthModal} />
    </section>
  );
}
