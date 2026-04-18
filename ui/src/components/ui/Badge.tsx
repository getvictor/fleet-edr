import classnames from "classnames";
import type { ReactNode } from "react";
import "./Badge.scss";

export type BadgeVariant =
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "success"
  | "info"
  | "neutral";

interface BadgeProps {
  variant?: BadgeVariant;
  children: ReactNode;
  className?: string;
}

export function Badge({ variant = "neutral", children, className }: BadgeProps) {
  const fullClassName = classnames("badge", `badge--${variant}`, className);
  return <span className={fullClassName}>{children}</span>;
}
