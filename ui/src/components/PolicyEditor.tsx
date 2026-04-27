import { useEffect, useState } from "react";
import { fetchPolicy, updatePolicy, type Policy } from "../api";
import { Table, EmptyState } from "./ui/Table";
import { PageHeader } from "./ui/PageHeader";
import { Button } from "./ui/Button";
import { Input } from "./ui/Input";
import "./PolicyEditor.scss";

// PolicyEditor is the operator-facing surface for the server-driven blocklist
// (the same Policy that GET/PUT /api/v1/admin/policy serves). The UI deliberately
// stays bare — list paths and hashes, add a row, remove a row, save with a
// required reason. Every save bumps the policy version on the server and fans
// out a set_blocklist command to every active host. The server canonicalises
// macOS symlink prefixes (/tmp/ → /private/tmp/, /var/ → /private/var/) so an
// operator who types /tmp/payload still gets a working block at the kernel.
export function PolicyEditor() {
  const [policy, setPolicy] = useState<Policy | null>(null);
  const [paths, setPaths] = useState<string[]>([]);
  const [hashes, setHashes] = useState<string[]>([]);
  const [newPath, setNewPath] = useState("");
  const [newHash, setNewHash] = useState("");
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [savedAt, setSavedAt] = useState<string | null>(null);

  useEffect(() => {
    fetchPolicy()
      .then((p) => {
        setPolicy(p);
        setPaths(p.blocklist.paths);
        setHashes(p.blocklist.hashes);
      })
      .catch((err: unknown) => {
        setError(err instanceof Error ? err.message : "Failed to load policy");
      });
  }, []);

  const dirty = policy !== null
    && (JSON.stringify(paths) !== JSON.stringify(policy.blocklist.paths)
      || JSON.stringify(hashes) !== JSON.stringify(policy.blocklist.hashes));

  const addPath = () => {
    const p = newPath.trim();
    if (!p || paths.includes(p)) return;
    setPaths([...paths, p].sort((a, b) => a.localeCompare(b)));
    setNewPath("");
  };

  const addHash = () => {
    const h = newHash.trim().toLowerCase();
    if (!h || hashes.includes(h)) return;
    setHashes([...hashes, h].sort((a, b) => a.localeCompare(b)));
    setNewHash("");
  };

  const removePath = (p: string) => { setPaths(paths.filter((x) => x !== p)); };
  const removeHash = (h: string) => { setHashes(hashes.filter((x) => x !== h)); };

  const handleSave = () => {
    if (!reason.trim()) {
      setError("Reason is required for every policy change.");
      return;
    }
    setSaving(true);
    setError(null);
    updatePolicy(paths, hashes, "ui", reason.trim())
      .then((p) => {
        setPolicy(p);
        setPaths(p.blocklist.paths);
        setHashes(p.blocklist.hashes);
        setReason("");
        setSavedAt(p.updated_at);
      })
      .catch((err: unknown) => {
        setError(err instanceof Error ? err.message : "Save failed");
      })
      .finally(() => { setSaving(false); });
  };

  return (
    <>
      <PageHeader
        title="Policy"
        subtitle="Server-driven blocklist that every host enforces under AUTH_EXEC."
      />

      {error && <div className="form-error" role="alert">Error: {error}</div>}

      <section className="policy-section">
        <h2>Blocked paths</h2>
        <p className="policy-hint">
          Absolute file paths the system extension will <strong>deny</strong> on
          exec. <code>/tmp/foo</code> and <code>/var/foo</code> are auto-rewritten
          to their <code>/private/...</code> canonical forms server-side.
        </p>
        {paths.length === 0
          ? <EmptyState>No paths blocked.</EmptyState>
          : (
            <Table>
              <thead><tr><th>Path</th><th></th></tr></thead>
              <tbody>
                {paths.map((p) => (
                  <tr key={p}>
                    <td><code>{p}</code></td>
                    <td>
                      <Button size="small" variant="inverse" onClick={() => { removePath(p); }}>
                        Remove
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </Table>
          )}
        <div className="policy-add-row">
          <Input
            id="new-path"
            label="Add path:"
            value={newPath}
            onChange={(e) => { setNewPath(e.target.value); }}
            placeholder="/private/tmp/payload"
          />
          <Button size="small" onClick={addPath}>Add</Button>
        </div>
      </section>

      <section className="policy-section">
        <h2>Blocked SHA-256 hashes</h2>
        <p className="policy-hint">
          64-character lowercase hex. Lets you block a binary regardless of where
          it lives on disk.
        </p>
        {hashes.length === 0
          ? <EmptyState>No hashes blocked.</EmptyState>
          : (
            <Table>
              <thead><tr><th>Hash</th><th></th></tr></thead>
              <tbody>
                {hashes.map((h) => (
                  <tr key={h}>
                    <td><code>{h}</code></td>
                    <td>
                      <Button size="small" variant="inverse" onClick={() => { removeHash(h); }}>
                        Remove
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </Table>
          )}
        <div className="policy-add-row">
          <Input
            id="new-hash"
            label="Add hash:"
            value={newHash}
            onChange={(e) => { setNewHash(e.target.value); }}
            placeholder="aaaaaaaa..."
          />
          <Button size="small" onClick={addHash}>Add</Button>
        </div>
      </section>

      <section className="policy-section">
        <h2>Save</h2>
        <p className="policy-hint">
          Every save bumps the policy version and fans the new blocklist out to
          every active host. The reason is recorded in the audit log.
        </p>
        <Input
          id="policy-reason"
          label="Reason:"
          value={reason}
          onChange={(e) => { setReason(e.target.value); }}
          placeholder="why are you changing the policy?"
        />
        <div className="policy-save-row">
          <Button onClick={handleSave} disabled={!dirty || saving || !reason.trim()}>
            {saving ? "Saving..." : "Save policy"}
          </Button>
          {policy && (
            <span className="policy-meta">
              version {policy.version}, last changed {new Date(policy.updated_at).toLocaleString()} by {policy.updated_by}
            </span>
          )}
          {savedAt && !dirty && (
            <span className="policy-saved">Saved.</span>
          )}
        </div>
      </section>
    </>
  );
}
