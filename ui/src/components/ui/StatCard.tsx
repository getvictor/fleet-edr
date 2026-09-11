import type { ReactNode } from "react";
import classnames from "classnames";
import "./StatCard.scss";

// Accent maps to a left-border colour token, never a raw hex. Kept colour-role
// rather than page-semantic so the card reuses across surfaces: the Hosts page
// strip uses green/red/neutral for online/offline/total, and the ATT&CK
// coverage strip uses green throughout.
export type StatCardAccent = "green" | "red" | "neutral";

interface StatCardProps {
  readonly value: ReactNode;
  readonly label: ReactNode;
  readonly accent?: StatCardAccent;
  // Longer explanation, shown on hover over the whole tile. The LABEL still has to stand on its own: this is detail for
  // a reader who wants it, never the sentence that decides what the number means. A caveat that changes the reading of
  // a figure belongs in visible text, for the reason the detection-tuning notes were moved out of a `title` attribute:
  // a native tooltip on a non-focusable element reaches neither keyboard nor touch users.
  readonly hint?: string;
}

// StatCard is a single labelled metric tile (big tabular number over an
// uppercase caption) with a coloured left accent border. SummaryStrip lays a
// row of them out above a table.
export function StatCard({ value, label, accent = "neutral", hint }: Readonly<StatCardProps>) {
  return (
    <div className={classnames("stat-card", `stat-card--${accent}`)} title={hint}>
      <span className="stat-card__value">{value}</span>
      <span className="stat-card__label">{label}</span>
    </div>
  );
}

export function SummaryStrip({ children }: { readonly children: ReactNode }) {
  return <div className="summary-strip">{children}</div>;
}
