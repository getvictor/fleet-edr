import classnames from "classnames";
import type { ButtonHTMLAttributes, ReactNode } from "react";
import "./Button.scss";

export type ButtonVariant = "primary" | "alert" | "inverse" | "text-link";
export type ButtonSize = "default" | "small";

interface ButtonProps extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, "size"> {
  readonly variant?: ButtonVariant;
  readonly size?: ButtonSize;
  readonly isLoading?: boolean;
  // fullWidth makes the button span its parent's full inline width
  // instead of shrinking to its content (the inline-flex default).
  // Standard for primary CTAs on auth cards, modal footers, and
  // form submits where the button IS the page's primary action.
  readonly fullWidth?: boolean;
  readonly children: ReactNode;
}

export function Button({
  variant = "primary",
  size = "default",
  isLoading = false,
  fullWidth = false,
  disabled,
  className,
  children,
  type = "button",
  ...rest
}: Readonly<ButtonProps>) {
  const fullClassName = classnames(
    "button",
    `button--${variant}`,
    {
      "button--small": size === "small",
      "button--full-width": fullWidth,
      "button--disabled": disabled || isLoading,
      "button--loading": isLoading,
    },
    className,
  );

  let buttonType: "submit" | "reset" | "button" = "button";
  if (type === "submit") buttonType = "submit";
  else if (type === "reset") buttonType = "reset";
  return (
    <button
      type={buttonType}
      className={fullClassName}
      disabled={disabled || isLoading}
      {...rest}
    >
      <span className="button__label">{children}</span>
    </button>
  );
}
