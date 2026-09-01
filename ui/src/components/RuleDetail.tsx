import { useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router";
import { fetchRuleDocs, type RuleDocEntry } from "../api";
import { PageHeader } from "./ui/PageHeader";
import { Table, EmptyState } from "./ui/Table";
import "./RuleDetail.scss";

// RuleDetail renders a single detection rule's documentation: behaviour,
// severity, ATT&CK mapping, false-positive sources, and
// limitations. This page loads rule docs from /api/rules; the
// markdown reference at docs/detection-rules.md is generated directly from
// the same Go-side `detection.Rule.Doc()` definitions, so the two surfaces
// stay aligned even though they don't share a fetch path.
//
// The /ui/coverage page links rule names here; if a future page lists alerts
// with rule IDs they should link here too. Unknown :ruleId renders an empty
// state pointing at the index, not a 404, so an old bookmark to a deleted
// rule still navigates somewhere actionable.

export function RuleDetail() {
  const { ruleId } = useParams<{ ruleId: string }>();
  const [entries, setEntries] = useState<RuleDocEntry[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetchRuleDocs()
      .then((rs) => {
        if (!cancelled) setEntries(rs);
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load rule docs");
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const entry = useMemo(() => entries?.find((e) => e.id === ruleId) ?? null, [entries, ruleId]);

  return (
    <>
      <PageHeader
        title={entry ? entry.doc.title : "Detection rule"}
        subtitle={entry ? <code className="rule-detail__id">{entry.id}</code> : ruleId}
      />

      {error && (
        <div className="form-error" role="alert">
          Error: {error}
        </div>
      )}
      {!error && entries === null && <EmptyState>Loading rule documentation...</EmptyState>}

      {!error && entries !== null && !entry && (
        <EmptyState>
          Unknown rule <code>{ruleId}</code>. <Link to="/coverage">Back to coverage</Link>.
        </EmptyState>
      )}

      {entry && <RuleBody entry={entry} />}
    </>
  );
}

// MODE_LABEL and MODE_EFFECT render a resolved mode for a reader. Held as maps rather than nested ternaries because there are three
// modes and two independent questions about them (what it is called, what it does), and a fourth mode would otherwise mean editing
// two conditionals in the markup.
const MODE_LABEL: Record<string, string> = {
  alert: "Alert",
  monitor: "Monitor",
  disabled: "Disabled",
};

const MODE_EFFECT: Record<string, string> = {
  alert: "This rule raises alerts as normal.",
  monitor: "This rule records what it would have fired on and raises no alert.",
  disabled: "This rule is off and produces nothing.",
};

// modeRow describes the Mode row for a rule, or null when the row says nothing a reader needs.
//
// The two shapes exist because a response that omits `mode` is NOT a response saying "no configuration applies". It is an older
// server that cannot answer the question: during a rolling deploy an older replica can return `default_mode: monitor` for a rule
// whose global setting is `disabled`, and presenting the declaration as the mode in force would state the opposite of the truth.
// So the row reports what it actually has, and says which.
function modeRow(entry: RuleDocEntry): { heading: string; mode: string; provenance: string; resolved: boolean } | null {
  if (entry.mode === undefined) {
    // Legacy shape: the declaration is all there is, and it is labelled as the declaration.
    if (!entry.default_mode || entry.default_mode === "alert") return null;
    return {
      heading: "Default mode",
      mode: entry.default_mode,
      provenance: "This server does not report the mode in force, so this is the rule's own declaration; a setting can override it.",
      resolved: false,
    };
  }
  const declared = entry.default_mode ?? "alert";
  // Worth a row when the rule does not alert, or alerts having been moved off the mode it declares.
  if (entry.mode === "alert" && entry.mode === declared) return null;
  return {
    heading: "Mode",
    mode: entry.mode,
    provenance:
      entry.mode_source === "setting"
        ? "An operator set this through the detection-config surface."
        : // Deliberately about where the MODE came from, not about whether a setting exists. A setting whose stored mode this
          // server cannot interpret also reports source `default`, and that setting can still carry an active severity override,
          // so "no setting applies" would be a claim this field does not support.
          "This is the mode the rule declares.",
    resolved: true,
  };
}

function RuleBody({ entry }: Readonly<{ entry: RuleDocEntry }>) {
  const { doc, techniques } = entry;
  return (
    <div className="rule-detail">
      <p className="rule-detail__summary">{doc.summary}</p>

      <Table className="rule-detail__meta">
        <tbody>
          <tr>
            <th scope="row">Severity</th>
            <td>
              <SeverityBadge severity={doc.severity} />
            </td>
          </tr>
          {/*
            A rule that does not alert is shown next to severity, because severity alone reads as a promise the rule does not make:
            "high" on a rule that never alerts is the most misleading pair on this page (issue #764). The row also appears for a
            rule an operator PROMOTED, since it now alerts for a reason a reader would otherwise have to guess at. A rule that
            alerts and always did stays uncluttered.
          */}
          {(() => {
            const row = modeRow(entry);
            if (row === null) return null;
            return (
              <tr>
                <th scope="row">{row.heading}</th>
                <td>
                  <span className="rule-detail__mode">{MODE_LABEL[row.mode] ?? row.mode}</span>{" "}
                  {MODE_EFFECT[row.mode] ?? "Its mode is not one this page recognises."} {row.provenance}
                  {/* Only claimed when a mode was actually resolved: saying "resolved at global scope" right after "this server
                      does not report the mode in force" is a contradiction in consecutive sentences. */}
                  {row.resolved && " Resolved at global scope; a host-group setting can differ for the hosts in that group."}
                </td>
              </tr>
            );
          })()}
          {entry.origin && (
            <tr>
              <th scope="row">Source</th>
              <td>{entry.origin}</td>
            </tr>
          )}
          <tr>
            <th scope="row">ATT&amp;CK</th>
            <td>
              {techniques.length === 0 ? (
                <span className="rule-detail__muted">no mapping</span>
              ) : (
                // Composite key (value + index) defends against an upstream
                // API ever returning a duplicate technique ID by accident -
                // React would otherwise reuse one DOM node for both entries
                // and confuse its reconciler.
                techniques.map((t, i) => (
                  <span key={`${t}-${String(i)}`}>
                    {i > 0 && ", "}
                    <a href={`https://attack.mitre.org/techniques/${t.replace(".", "/")}/`} target="_blank" rel="noopener noreferrer">
                      <code>{t}</code>
                    </a>
                  </span>
                ))
              )}
            </td>
          </tr>
          <tr>
            <th scope="row">Event types</th>
            <td>
              {doc.event_types.map((t, i) => (
                <span key={`${t}-${String(i)}`}>
                  {i > 0 && ", "}
                  <code>{t}</code>
                </span>
              ))}
            </td>
          </tr>
        </tbody>
      </Table>

      <h2>Description</h2>
      {/* Description is plain text from the Go side; we split on blank lines
          so paragraphs render. The .rule-detail__para class applies
          `white-space: pre-line` so single newlines inside a paragraph
          (e.g. the numbered list in suspicious_exec's description) survive
          rather than collapsing the way HTML normally would. */}
      {doc.description.split("\n\n").map((para, i) => (
        <p key={`${entry.id}-p${String(i)}`} className="rule-detail__para">
          {para}
        </p>
      ))}

      {doc.false_positives && doc.false_positives.length > 0 && (
        <>
          <h2>Known false-positive sources</h2>
          <ul className="rule-detail__list">
            {doc.false_positives.map((fp, i) => (
              <li key={`${fp}-${String(i)}`}>{fp}</li>
            ))}
          </ul>
        </>
      )}

      {doc.limitations && doc.limitations.length > 0 && (
        <>
          <h2>Limitations</h2>
          <ul className="rule-detail__list">
            {doc.limitations.map((l, i) => (
              <li key={`${l}-${String(i)}`}>{l}</li>
            ))}
          </ul>
        </>
      )}

      {doc.references && doc.references.length > 0 && (
        <>
          <h2>References</h2>
          <ul className="rule-detail__list">
            {doc.references.map((ref, i) => (
              <li key={`${ref}-${String(i)}`}>
                {/* A reference on an imported rule is third-party text from the upstream YAML, so it is not trusted to be a
                    safe href: `javascript:` and `data:` URLs in an anchor are script execution on click. Anything that is not
                    plainly http(s) is rendered as text, which still shows the operator what the rule cited while making it
                    inert. Vetted links open in a new tab with noopener so the opened page cannot reach back through
                    window.opener. */}
                {isHTTPURL(ref) ? (
                  <a href={ref} target="_blank" rel="noopener noreferrer">
                    {ref}
                  </a>
                ) : (
                  ref
                )}
              </li>
            ))}
          </ul>
        </>
      )}

      <p className="rule-detail__back">
        <Link to="/coverage">&larr; Back to ATT&amp;CK coverage</Link>
      </p>
    </div>
  );
}

// KNOWN_SEVERITIES gates which class-name modifier we generate so unexpected
// upstream values cannot inject extra/empty CSS classes (Sonar
// typescript:S6749 / S7924). Anything outside this allowlist falls back to
// the unstyled neutral pill.
const KNOWN_SEVERITIES = ["low", "medium", "high", "critical"] as const;
type KnownSeverity = (typeof KNOWN_SEVERITIES)[number];
function isKnownSeverity(s: string): s is KnownSeverity {
  return (KNOWN_SEVERITIES as readonly string[]).includes(s);
}

// SeverityBadge picks a colour for the severity string. The four levels
// match the constants in server/detection/rule.go; an unknown level falls
// back to the neutral pill rather than producing a `rule-detail__sev--`
// class with whitespace or arbitrary content.
function SeverityBadge({ severity }: Readonly<{ severity: string }>) {
  const variant = isKnownSeverity(severity) ? severity : "unknown";
  const klass = `rule-detail__sev rule-detail__sev--${variant}`;
  return <span className={klass}>{severity}</span>;
}

// isHTTPURL reports whether a rule reference is safe to render as a link.
//
// References ride in from an upstream rule file, which is content this project vendors rather than writes, so the scheme is
// checked rather than assumed. An allowlist (http, https) rather than a denylist of the schemes known to be dangerous today:
// a denylist has to be updated every time a browser grows a new one, and getting that wrong turns a detection rule's citation
// into script execution.
function isHTTPURL(raw: string): boolean {
  try {
    const { protocol } = new URL(raw);
    return protocol === "http:" || protocol === "https:";
  } catch {
    // Not a parseable absolute URL (a bare path, a DOI, free text). Rendered as plain text by the caller.
    return false;
  }
}
