import { useState } from "react";
import "./FilterChips.scss";
import { Button } from "../ui/Button";

// FilterField is one searchable dimension: its URL param key and a human label. The signing field carries a fixed option set so the
// chip input offers the verdict vocabulary rather than a free-text value.
export interface FilterField {
  key: string;
  label: string;
  options?: { value: string; label: string }[];
}

interface FilterChipsProps {
  readonly fields: FilterField[];
  // active is the current filter values keyed by field key (from the URL); onChange replaces one field's value ("" removes it).
  readonly active: Record<string, string>;
  readonly onChange: (key: string, value: string) => void;
}

// FilterChips renders the active filters as removable chips and an add-filter row (a field select + a value control). It is the
// UI's filter-token surface for the search page (issue #582): chips reflect the URL params, and changing one pushes a new query.
export function FilterChips({ fields, active, onChange }: FilterChipsProps) {
  const byKey = new Map(fields.map((f) => [f.key, f]));
  const activeEntries = fields.filter((f) => active[f.key]);
  const available = fields.filter((f) => !active[f.key]);

  const [addKey, setAddKey] = useState("");
  const [addValue, setAddValue] = useState("");

  const addField = addKey ? byKey.get(addKey) : undefined;

  // Changing the field keeps a typed free-text value when the next field is also free-text, so reconsidering the field mid-type does
  // not wipe the entry; it resets when the value vocabulary changes (moving to or from a fixed-option field, or clearing the field).
  const changeField = (nextKey: string) => {
    const nextField = nextKey ? byKey.get(nextKey) : undefined;
    const prevIsFreeText = addField !== undefined && addField.options === undefined;
    const nextIsFreeText = nextField !== undefined && nextField.options === undefined;
    if (!prevIsFreeText || !nextIsFreeText) setAddValue("");
    setAddKey(nextKey);
  };

  const commitAdd = () => {
    if (!addKey || !addValue) return;
    onChange(addKey, addValue);
    setAddKey("");
    setAddValue("");
  };

  return (
    <div className="filter-chips">
      {activeEntries.map((f) => (
        <span key={f.key} className="filter-chips__chip">
          <span className="filter-chips__chip-label">
            {f.label}: {chipDisplay(f, active[f.key])}
          </span>
          <button
            type="button"
            className="filter-chips__remove"
            aria-label={`Remove ${f.label} filter`}
            onClick={() => { onChange(f.key, ""); }}
          >
            &times;
          </button>
        </span>
      ))}

      <span className="filter-chips__add">
        <select
          className="field__input"
          aria-label="Add filter field"
          value={addKey}
          onChange={(e) => { changeField(e.target.value); }}
        >
          <option value="">Add filter...</option>
          {available.map((f) => (
            <option key={f.key} value={f.key}>{f.label}</option>
          ))}
        </select>
        {/* The value control + Add appear only once a field is chosen, so the value is never a disabled dead input. */}
        {addField && (
          <>
            {addField.options ? (
              <select
                className="field__input filter-chips__value"
                aria-label={`${addField.label} value`}
                value={addValue}
                onChange={(e) => { setAddValue(e.target.value); }}
              >
                <option value="">Select...</option>
                {addField.options.map((o) => (
                  <option key={o.value} value={o.value}>{o.label}</option>
                ))}
              </select>
            ) : (
              <input
                className="field__input filter-chips__value"
                aria-label={`${addField.label} value`}
                placeholder={`Filter by ${addField.label.toLowerCase()}`}
                value={addValue}
                autoFocus
                onChange={(e) => { setAddValue(e.target.value); }}
                onKeyDown={(e) => { if (e.key === "Enter") commitAdd(); }}
              />
            )}
            <Button onClick={commitAdd} disabled={!addValue}>Add</Button>
          </>
        )}
      </span>
    </div>
  );
}

// chipDisplay renders a value's label: an option's human label when the field has a fixed set, else the raw value.
function chipDisplay(field: FilterField, value: string): string {
  return field.options?.find((o) => o.value === value)?.label ?? value;
}
