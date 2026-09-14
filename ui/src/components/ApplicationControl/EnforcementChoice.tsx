import type { Enforcement } from "../../api";
import "./ApplicationControl.scss";

interface EnforcementChoiceProps {
  // name groups the radio inputs; each form passes its own so two open dialogs cannot share a selection.
  readonly name: string;
  readonly value: Enforcement | null;
  readonly onChange: (value: Enforcement) => void;
  readonly disabled?: boolean;
}

const OPTIONS: readonly { value: Enforcement; label: string; help: string }[] = [
  {
    value: "DETECT",
    label: "Detect",
    help: "Let the executable run and keep a record of each match, to see what the rule would block before it blocks anything.",
  },
  { value: "PROTECT", label: "Protect", help: "Block the executable." },
];

// EnforcementChoice asks what a rule does when it matches, with neither answer selected: the server requires one, and either chosen
// by default is wrong for someone. Protect by default turns a rule meant to be watched into one that blocks production; Detect by
// default turns a rule meant to stop a known-bad binary into one that only records it.
export function EnforcementChoice({ name, value, onChange, disabled }: EnforcementChoiceProps) {
  return (
    <fieldset className="app-control-enforcement" disabled={disabled}>
      <legend className="field__label">Enforcement</legend>
      {OPTIONS.map((option) => (
        <label key={option.value} className="app-control-enforcement__option">
          <input
            type="radio"
            name={name}
            value={option.value}
            checked={value === option.value}
            onChange={() => {
              onChange(option.value);
            }}
          />
          <span>
            <span className="app-control-enforcement__label">{option.label}</span>
            <span className="app-control-enforcement__help">{option.help}</span>
          </span>
        </label>
      ))}
    </fieldset>
  );
}
