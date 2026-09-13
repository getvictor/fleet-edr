import { useEffect, useState } from "react";
import { getRuleContentDocument, listRuleContentDocuments, ruleDocumentStem } from "../api";
import "./RuleSource.scss";

type SourceState =
  | { kind: "loading" }
  | { kind: "document"; path: string; content: string }
  | { kind: "builtin" }
  | { kind: "error"; message: string };

// RuleSource shows the file a rule is loaded from, as written (issue #1001). Rules loaded from the stored corpus are Sigma YAML with an
// x-engine block, and reading one as written is how an operator sees exactly what it matches. A rule built into the server is not loaded
// from that corpus, and says so rather than showing an empty panel.
//
// The owning page renders this only for an operator with rule_content.read, since both reads here are gated on it.
export function RuleSource({ ruleId }: { readonly ruleId: string }) {
  const [state, setState] = useState<SourceState>({ kind: "loading" });

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
          <pre className="rule-source__content">{state.content}</pre>
        </>
      )}
    </section>
  );
}
