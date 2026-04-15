import classnames from "classnames";
import type { HTMLAttributes, ReactNode } from "react";
import "./Card.scss";

interface CardProps extends HTMLAttributes<HTMLDivElement> {
  padding?: "small" | "medium" | "large";
  children: ReactNode;
}

export function Card({
  padding = "medium",
  className,
  children,
  ...rest
}: CardProps) {
  const fullClassName = classnames(
    "card",
    `card--padding-${padding}`,
    className,
  );

  return (
    <div className={fullClassName} {...rest}>
      {children}
    </div>
  );
}
