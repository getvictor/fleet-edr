import classnames from "classnames";
import type { HTMLAttributes, ReactNode } from "react";
import "./Card.scss";

interface CardProps extends HTMLAttributes<HTMLDivElement> {
  readonly padding?: "small" | "medium" | "large";
  readonly children: ReactNode;
}

export function Card({
  padding = "medium",
  className,
  children,
  ...rest
}: Readonly<CardProps>) {
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
