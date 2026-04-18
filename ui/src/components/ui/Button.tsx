import classnames from "classnames";
import type { ButtonHTMLAttributes, ReactNode } from "react";
import "./Button.scss";

export type ButtonVariant = "primary" | "alert" | "inverse" | "text-link";
export type ButtonSize = "default" | "small";

interface ButtonProps extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, "size"> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  isLoading?: boolean;
  children: ReactNode;
}

export function Button({
  variant = "primary",
  size = "default",
  isLoading = false,
  disabled,
  className,
  children,
  type = "button",
  ...rest
}: ButtonProps) {
  const fullClassName = classnames(
    "button",
    `button--${variant}`,
    {
      "button--small": size === "small",
      "button--disabled": disabled || isLoading,
      "button--loading": isLoading,
    },
    className,
  );

  return (
    <button
      type={type === "submit" ? "submit" : type === "reset" ? "reset" : "button"}
      className={fullClassName}
      disabled={disabled || isLoading}
      {...rest}
    >
      <span className="button__label">{children}</span>
    </button>
  );
}
