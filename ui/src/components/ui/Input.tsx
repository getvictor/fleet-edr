import type { InputHTMLAttributes, SelectHTMLAttributes, ReactNode } from "react";
import classnames from "classnames";
import "./Input.scss";

interface InputProps extends InputHTMLAttributes<HTMLInputElement> {
  readonly label?: string;
}

export function Input({ label, id, className, ...rest }: Readonly<InputProps>) {
  return (
    <div className="field">
      {label && (
        <label htmlFor={id} className="field__label">
          {label}
        </label>
      )}
      <input id={id} className={classnames("field__input", className)} {...rest} />
    </div>
  );
}

interface SelectProps extends SelectHTMLAttributes<HTMLSelectElement> {
  readonly label?: string;
  readonly children: ReactNode;
}

export function Select({ label, id, className, children, ...rest }: Readonly<SelectProps>) {
  return (
    <div className="field field--inline">
      {label && (
        <label htmlFor={id} className="field__label field__label--inline">
          {label}
        </label>
      )}
      <select id={id} className={classnames("field__input", className)} {...rest}>
        {children}
      </select>
    </div>
  );
}
