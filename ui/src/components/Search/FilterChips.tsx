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
          aria-label="Add filter field"
          value={addKey}
          onChange={(e) => { setAddKey(e.target.value); setAddValue(""); }}
        >
          <option value="">Add filter...</option>
          {available.map((f) => (
            <option key={f.key} value={f.key}>{f.label}</option>
          ))}
        </select>
        {addField?.options ? (
          <select aria-label={`${addField.label} value`} value={addValue} onChange={(e) => { setAddValue(e.target.value); }}>
            <option value="">Select...</option>
            {addField.options.map((o) => (
              <option key={o.value} value={o.value}>{o.label}</option>
            ))}
          </select>
        ) : (
          <input
            aria-label={addField ? `${addField.label} value` : "Filter value"}
            disabled={!addField}
            value={addValue}
            onChange={(e) => { setAddValue(e.target.value); }}
            onKeyDown={(e) => { if (e.key === "Enter") commitAdd(); }}
          />
        )}
        <Button size="small" onClick={commitAdd}>Add</Button>
      </span>
    </div>
  );
}

// chipDisplay renders a value's label: an option's human label when the field has a fixed set, else the raw value.
function chipDisplay(field: FilterField, value: string): string {
  return field.options?.find((o) => o.value === value)?.label ?? value;
}
