import { useEffect, useState } from "react";
import {
  listWebhooks,
  createWebhook,
  updateWebhook,
  deleteWebhook,
  listWebhookDeliveries,
  type WebhookDestination,
  type WebhookDestinationInput,
  type WebhookDelivery,
} from "../../api";
import { PageHeader } from "../ui/PageHeader";
import { Card } from "../ui/Card";
import { Button } from "../ui/Button";
import { Input, Select } from "../ui/Input";
import { Badge } from "../ui/Badge";
import "./Webhooks.scss";

const EVENT_CREATED = "alert.created";
const EVENT_STATUS_CHANGED = "alert.status_changed";
const SEVERITIES = ["low", "medium", "high", "critical"];

// FormState mirrors the operator-editable fields. The signing secret is write-only: empty unless the operator is setting or rotating
// it. editingId is null for the add form and the destination id when editing an existing one.
interface FormState {
  editingId: number | null;
  name: string;
  url: string;
  onCreated: boolean;
  onStatusChanged: boolean;
  minSeverity: string;
  enabled: boolean;
  secret: string;
}

function emptyForm(): FormState {
  return { editingId: null, name: "", url: "", onCreated: true, onStatusChanged: false, minSeverity: "low", enabled: true, secret: "" };
}

function toForm(d: WebhookDestination): FormState {
  return {
    editingId: d.id,
    name: d.name,
    url: d.url,
    onCreated: d.event_types.includes(EVENT_CREATED),
    onStatusChanged: d.event_types.includes(EVENT_STATUS_CHANGED),
    minSeverity: d.min_severity,
    enabled: d.enabled,
    secret: "",
  };
}

function isHTTPSURL(raw: string): boolean {
  try {
    const u = new URL(raw.trim());
    return u.protocol === "https:" && u.host !== "";
  } catch {
    return false;
  }
}

export function Webhooks() {
  const [destinations, setDestinations] = useState<WebhookDestination[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [form, setForm] = useState<FormState>(emptyForm());
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  const [deliveries, setDeliveries] = useState<{ id: number; rows: WebhookDelivery[] } | null>(null);

  // refresh reloads the list and handles its own error, so a reload failure after a successful create/update/delete surfaces as a
  // load error rather than being caught by the caller's try/catch and misreported as a save/delete failure (Copilot, Qodo).
  async function refresh() {
    try {
      setDestinations(await listWebhooks());
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to reload webhooks");
    }
  }

  useEffect(() => {
    let cancelled = false;
    listWebhooks()
      .then((d) => {
        if (!cancelled) setDestinations(d);
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load webhooks");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  function update<K extends keyof FormState>(key: K, value: FormState[K]) {
    setForm((prev) => ({ ...prev, [key]: value }));
    setSaved(false);
  }

  function validate(f: FormState): string | null {
    if (f.name.trim() === "") return "Name is required.";
    if (!isHTTPSURL(f.url)) return "URL must be a valid https URL.";
    if (!f.onCreated && !f.onStatusChanged) return "Select at least one event type.";
    if (f.editingId === null && f.secret.trim() === "") return "A signing secret is required.";
    return null;
  }

  async function handleSave() {
    const invalid = validate(form);
    if (invalid !== null) {
      setSaveError(invalid);
      return;
    }
    setSaving(true);
    setSaveError(null);
    setSaved(false);
    const eventTypes: string[] = [];
    if (form.onCreated) eventTypes.push(EVENT_CREATED);
    if (form.onStatusChanged) eventTypes.push(EVENT_STATUS_CHANGED);
    const secret = form.secret.trim();
    const body: WebhookDestinationInput = {
      name: form.name.trim(),
      url: form.url.trim(),
      event_types: eventTypes,
      min_severity: form.minSeverity,
      enabled: form.enabled,
      ...(secret === "" ? {} : { secret }),
    };
    try {
      if (form.editingId === null) await createWebhook(body);
      else await updateWebhook(form.editingId, body);
      setForm(emptyForm());
      setSaved(true);
      await refresh();
    } catch (err: unknown) {
      setSaveError(err instanceof Error ? err.message : "Failed to save webhook.");
    } finally {
      setSaving(false);
    }
  }

  async function handleDelete(id: number) {
    if (!globalThis.confirm("Delete this webhook destination? Queued deliveries to it are discarded.")) return;
    try {
      await deleteWebhook(id);
      if (deliveries?.id === id) setDeliveries(null);
      if (form.editingId === id) setForm(emptyForm());
      await refresh();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to delete webhook.");
    }
  }

  async function viewDeliveries(id: number) {
    try {
      setDeliveries({ id, rows: await listWebhookDeliveries(id) });
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to load deliveries.");
    }
  }

  if (loading) return <div className="webhooks">Loading</div>;

  return (
    <div className="webhooks">
      <PageHeader title="Webhooks" subtitle="Deliver alerts to an external endpoint over a signed HTTPS POST." />
      {error !== null && (
        <div className="webhooks__error" role="alert">
          {error}
        </div>
      )}

      <Card padding="large">
        <h3>{form.editingId === null ? "Add destination" : "Edit destination"}</h3>
        <Input id="wh-name" label="Name" value={form.name} onChange={(e) => { update("name", e.target.value); }} />
        <Input
          id="wh-url"
          label="URL"
          type="text"
          placeholder="https://hooks.example.com/edr"
          value={form.url}
          onChange={(e) => { update("url", e.target.value); }}
        />
        <fieldset className="webhooks__events">
          <legend>Events</legend>
          <label>
            <input type="checkbox" checked={form.onCreated} onChange={(e) => { update("onCreated", e.target.checked); }} /> Alert created
          </label>
          <label>
            <input type="checkbox" checked={form.onStatusChanged} onChange={(e) => { update("onStatusChanged", e.target.checked); }} /> Status changed
          </label>
        </fieldset>
        <Select id="wh-severity" label="Minimum severity" value={form.minSeverity} onChange={(e) => { update("minSeverity", e.target.value); }} inline>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </Select>
        <label className="webhooks__enabled">
          <input type="checkbox" checked={form.enabled} onChange={(e) => { update("enabled", e.target.checked); }} /> Enabled
        </label>
        <Input
          id="wh-secret"
          label="Signing secret"
          type="password"
          autoComplete="off"
          data-1p-ignore=""
          data-lpignore="true"
          data-form-type="other"
          placeholder={form.editingId !== null ? "•••••• enter a new value to rotate" : "enter the signing secret"}
          value={form.secret}
          onChange={(e) => { update("secret", e.target.value); }}
        />
        <div className="webhooks__actions">
          <Button type="button" variant="primary" isLoading={saving} onClick={() => void handleSave()}>
            {form.editingId === null ? "Add destination" : "Save changes"}
          </Button>
          {form.editingId !== null && (
            <Button
              type="button"
              variant="inverse"
              onClick={() => {
                setForm(emptyForm());
                setSaved(false);
              }}
            >
              Cancel
            </Button>
          )}
        </div>
        {saveError !== null && (
          <div className="webhooks__save-error" role="alert">
            {saveError}
          </div>
        )}
        {saved && (
          <output className="webhooks__saved" aria-live="polite">
            Saved.
          </output>
        )}
      </Card>

      <Card padding="large">
        <h3>Destinations</h3>
        {destinations !== null && destinations.length === 0 && <p>No destinations configured.</p>}
        {destinations !== null && destinations.length > 0 && (
          <table className="webhooks__table">
            <thead>
              <tr>
                <th>Name</th>
                <th>URL</th>
                <th>Events</th>
                <th>Min severity</th>
                <th>Status</th>
                <th aria-label="Actions" />
              </tr>
            </thead>
            <tbody>
              {destinations.map((d) => (
                <tr key={d.id}>
                  <td>{d.name}</td>
                  <td>{d.url}</td>
                  <td>{d.event_types.join(", ")}</td>
                  <td>{d.min_severity}</td>
                  <td>{d.enabled ? <Badge variant="success">Enabled</Badge> : <Badge variant="neutral">Disabled</Badge>}</td>
                  <td>
                    <Button type="button" variant="text-link" size="small" onClick={() => { setForm(toForm(d)); }}>
                      Edit
                    </Button>
                    <Button type="button" variant="text-link" size="small" onClick={() => void viewDeliveries(d.id)}>
                      Deliveries
                    </Button>
                    <Button type="button" variant="text-link" size="small" onClick={() => void handleDelete(d.id)}>
                      Delete
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>

      {deliveries !== null && (
        <Card padding="large">
          <h3>Recent deliveries</h3>
          {deliveries.rows.length === 0 && <p>No deliveries yet.</p>}
          {deliveries.rows.length > 0 && (
            <table className="webhooks__table">
              <thead>
                <tr>
                  <th>Event</th>
                  <th>Status</th>
                  <th>Attempt</th>
                  <th>HTTP</th>
                  <th>Last error</th>
                </tr>
              </thead>
              <tbody>
                {deliveries.rows.map((r) => (
                  <tr key={r.id}>
                    <td>{r.event_type}</td>
                    <td>{r.status}</td>
                    <td>{r.attempt}</td>
                    <td>{r.last_status_code ?? "-"}</td>
                    <td>{r.last_error ?? ""}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      )}
    </div>
  );
}
