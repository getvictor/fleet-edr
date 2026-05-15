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
  // inline controls the label layout. true (default) renders the
  // label beside the control in mixed case + regular weight, which
  // fits filter-bar rows like the alerts page. false stacks the
  // label above the control in the same uppercase + bold treatment
  // Input uses, which is what dialog forms want so a Select sits
  // visually next to sibling Input fields without a font-style break.
  readonly inline?: boolean;
}

export function Select({ label, id, className, children, inline = true, ...rest }: Readonly<SelectProps>) {
  return (
    <div className={classnames("field", inline && "field--inline")}>
      {label && (
        <label
          htmlFor={id}
          className={classnames("field__label", inline && "field__label--inline")}
        >
          {label}
        </label>
      )}
      <select id={id} className={classnames("field__input", className)} {...rest}>
        {children}
      </select>
    </div>
  );
}
