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
}

// StatCard is a single labelled metric tile (big tabular number over an
// uppercase caption) with a coloured left accent border. SummaryStrip lays a
// row of them out above a table.
export function StatCard({ value, label, accent = "neutral" }: Readonly<StatCardProps>) {
  return (
    <div className={classnames("stat-card", `stat-card--${accent}`)}>
      <span className="stat-card__value">{value}</span>
      <span className="stat-card__label">{label}</span>
    </div>
  );
}

export function SummaryStrip({ children }: { readonly children: ReactNode }) {
  return <div className="summary-strip">{children}</div>;
}
