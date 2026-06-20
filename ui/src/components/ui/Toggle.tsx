import type { InputHTMLAttributes } from "react";
import "./Toggle.scss";

interface ToggleProps extends Omit<InputHTMLAttributes<HTMLInputElement>, "type"> {
  // label renders to the right of the switch and is associated via the wrapping <label>.
  readonly label?: string;
}

// Toggle is an accessible on/off switch: a visually-hidden checkbox (role="switch") drives
// a styled track + knob, so keyboard focus, the space key, and screen readers all work
// while matching the Fleet design (44x24 pill, green when on). There is no native switch
// element, so a checkbox is the correct ARIA base.
export function Toggle({ label, id, ...rest }: ToggleProps) {
  return (
    <label className="toggle" htmlFor={id}>
      <span className="toggle__control">
        <input id={id} type="checkbox" role="switch" className="toggle__input" {...rest} />
        <span className="toggle__track" aria-hidden="true">
          <span className="toggle__knob" />
        </span>
      </span>
      {label !== undefined && <span className="toggle__label">{label}</span>}
    </label>
  );
}
