import type { ReactNode, HTMLAttributes } from "react";
import classnames from "classnames";
import "./Table.scss";

interface TableProps extends HTMLAttributes<HTMLTableElement> {
  children: ReactNode;
}

export function Table({ className, children, ...rest }: TableProps) {
  return (
    <div className="table-wrapper">
      <table className={classnames("table", className)} {...rest}>
        {children}
      </table>
    </div>
  );
}

export function EmptyState({ children }: { children: ReactNode }) {
  return <div className="table-empty">{children}</div>;
}
