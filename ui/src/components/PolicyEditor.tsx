import { useEffect, useState } from "react";
import { fetchPolicy, updatePolicy, type Policy } from "../api";
import { Table, EmptyState } from "./ui/Table";
import { PageHeader } from "./ui/PageHeader";
import { Button } from "./ui/Button";
import { Input } from "./ui/Input";
import "./PolicyEditor.scss";

interface PolicyEditorProps {
  // actor is the authenticated operator's email — recorded in updated_by on
  // the server and emitted to the audit log on every change. Required so a
  // post-incident reviewer can answer "who pushed this rule?" without
  // resorting to session-cookie forensics.
  readonly actor: string;
}

const HEX_64 = /^[0-9a-f]{64}$/;

function sortedEqual(a: readonly string[], b: readonly string[]): boolean {
  if (a.length !== b.length) return false;
  // Pass an explicit Intl-aware comparator instead of relying on Array.sort's
  // default lexicographic-by-UTF-16-unit ordering (Sonar typescript:S2871).
  // For ASCII-only inputs the result is identical; for unicode it's correct
  // and locale-stable.
  const cmp = (x: string, y: string) => x.localeCompare(y);
  const sa = [...a].sort(cmp);
  const sb = [...b].sort(cmp);
  // Indexed access is safe: i is bounded by sa.length (== sb.length checked above).
  // eslint-disable-next-line security/detect-object-injection
  return sa.every((v, i) => v === sb[i]);
}

// listDiff returns the count of items added vs removed when going from `prev`
// to `next`. Used by the save bar so the operator sees true change shape (e.g.
// "+1, -1") rather than just the net length delta.
function listDiff(next: readonly string[], prev: readonly string[]): { added: number; removed: number } {
  const prevSet = new Set(prev);
  const nextSet = new Set(next);
  let added = 0;
  let removed = 0;
  for (const v of next) if (!prevSet.has(v)) added += 1;
  for (const v of prev) if (!nextSet.has(v)) removed += 1;
  return { added, removed };
}

function hasDiff(d: { added: number; removed: number }): boolean {
  return d.added > 0 || d.removed > 0;
}

function renderDiff(d: { added: number; removed: number }, singular: string, plural: string): string {
  if (!hasDiff(d)) return "";
  const total = d.added + d.removed;
  const noun = total === 1 ? singular : plural;
  const parts: string[] = [];
  if (d.added > 0) parts.push(`+${String(d.added)}`);
  if (d.removed > 0) parts.push(`-${String(d.removed)}`);
  return `${parts.join("/")} ${noun}`;
}

// PolicyEditor is the operator-facing surface for the server-driven blocklist
// (the same Policy that GET/PUT /api/policy serves). The flow follows
// the pattern most enterprise dashboards use (GitHub, Atlassian, AWS Console):
// the page edits a *staged* copy of the policy; nothing hits the server until
// the operator clicks "Save changes" in a sticky footer that only appears when
// there are unsaved edits. Add/remove buttons mutate the staged copy, not
// the live policy. The footer also takes the audit reason in-line so the
// operator sees both controls together.
//
// The server canonicalises macOS symlink prefixes (/tmp/ → /private/tmp/,
// /var/ → /private/var/, /etc/ → /private/etc/) so an operator who types
// /tmp/payload still gets a working block at the kernel.
export function PolicyEditor({ actor }: PolicyEditorProps) {
  const [policy, setPolicy] = useState<Policy | null>(null);
  const [paths, setPaths] = useState<string[]>([]);
  const [hashes, setHashes] = useState<string[]>([]);
  const [newPath, setNewPath] = useState("");
  const [newHash, setNewHash] = useState("");
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [savedFlash, setSavedFlash] = useState(false);

  useEffect(() => {
    let cancelled = false;
    fetchPolicy()
      .then((p) => {
        if (cancelled) return;
        setPolicy(p);
        setPaths(p.blocklist.paths);
        setHashes(p.blocklist.hashes);
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        setError(err instanceof Error ? err.message : "Failed to load policy");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => { cancelled = true; };
  }, []);

  const dirty = policy !== null
    && (!sortedEqual(paths, policy.blocklist.paths)
      || !sortedEqual(hashes, policy.blocklist.hashes));

  // Real add/remove counts (not just net length deltas) — operators often add
  // one entry while removing another during cleanup, and a length-only delta
  // would silently report "list reordered" when the content actually changed.
  const pathDiff = policy ? listDiff(paths, policy.blocklist.paths) : { added: 0, removed: 0 };
  const hashDiff = policy ? listDiff(hashes, policy.blocklist.hashes) : { added: 0, removed: 0 };

  const addPath = () => {
    const p = newPath.trim();
    if (!p) return;
    if (!p.startsWith("/")) {
      setError("Path must be absolute (start with '/').");
      return;
    }
    if (paths.includes(p)) {
      setNewPath("");
      return;
    }
    setError(null);
    setPaths([...paths, p].sort((a, b) => a.localeCompare(b)));
    setNewPath("");
    setSavedFlash(false);
  };

  const addHash = () => {
    const h = newHash.trim().toLowerCase();
    if (!h) return;
    if (!HEX_64.test(h)) {
      setError("Hash must be exactly 64 lowercase hex characters (SHA-256).");
      return;
    }
    if (hashes.includes(h)) {
      setNewHash("");
      return;
    }
    setError(null);
    setHashes([...hashes, h].sort((a, b) => a.localeCompare(b)));
    setNewHash("");
    setSavedFlash(false);
  };

  const removePath = (p: string) => {
    setPaths(paths.filter((x) => x !== p));
    setSavedFlash(false);
  };
  const removeHash = (h: string) => {
    setHashes(hashes.filter((x) => x !== h));
    setSavedFlash(false);
  };

  const discardChanges = () => {
    if (!policy) return;
    setPaths(policy.blocklist.paths);
    setHashes(policy.blocklist.hashes);
    setNewPath("");
    setNewHash("");
    setReason("");
    setError(null);
  };

  const handleSave = () => {
    if (!reason.trim()) {
      setError("A reason is required for the audit log.");
      return;
    }
    setSaving(true);
    setError(null);
    updatePolicy(paths, hashes, actor, reason.trim())
      .then((p) => {
        setPolicy(p);
        setPaths(p.blocklist.paths);
        setHashes(p.blocklist.hashes);
        setReason("");
        setSavedFlash(true);
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
      {loading && <EmptyState>Loading policy...</EmptyState>}

      {!loading && (
        <>
          {savedFlash && !dirty && (
            <output className="policy-flash">
              Policy saved. Version {policy?.version}, fanned out to all active hosts.
            </output>
          )}

          <section className="policy-section">
            <h2>Blocked paths</h2>
            <p className="policy-hint">
              Absolute file paths the system extension will <strong>deny</strong> on
              exec. <code>/tmp/foo</code>, <code>/var/foo</code>, and <code>/etc/foo</code>{" "}
              are auto-rewritten to their <code>/private/...</code> canonical forms
              server-side.
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
            <form
              className="policy-add-row"
              onSubmit={(e) => { e.preventDefault(); addPath(); }}
            >
              <Input
                id="new-path"
                label="Add path:"
                value={newPath}
                onChange={(e) => { setNewPath(e.target.value); }}
                placeholder="e.g. /private/tmp/payload"
              />
              <Button size="small" type="submit">Add path</Button>
            </form>
          </section>

          <section className="policy-section">
            <h2>Blocked SHA-256 hashes</h2>
            <p className="policy-hint">
              64-character lowercase hex. Lets you block a binary regardless of
              where it lives on disk.
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
            <form
              className="policy-add-row"
              onSubmit={(e) => { e.preventDefault(); addHash(); }}
            >
              <Input
                id="new-hash"
                label="Add hash:"
                value={newHash}
                onChange={(e) => { setNewHash(e.target.value); }}
                placeholder="e.g. e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
              />
              <Button size="small" type="submit">Add hash</Button>
            </form>
          </section>

          {policy && (
            <p className="policy-meta">
              Currently live: version {policy.version}, last changed{" "}
              {new Date(policy.updated_at).toLocaleString()} by {policy.updated_by}.
            </p>
          )}

          {dirty && (
            <section
              className="policy-savebar"
              aria-labelledby="policy-savebar-heading"
            >
              <div className="policy-savebar__summary">
                <strong id="policy-savebar-heading">Unsaved changes:</strong>{" "}
                <span className="policy-savebar__delta">
                  {renderDiff(pathDiff, "path", "paths")}
                  {hasDiff(pathDiff) && hasDiff(hashDiff) && ", "}
                  {renderDiff(hashDiff, "hash", "hashes")}
                  {!hasDiff(pathDiff) && !hasDiff(hashDiff) && "items reordered"}
                </span>
              </div>
              <form
                className="policy-savebar__form"
                onSubmit={(e) => { e.preventDefault(); handleSave(); }}
              >
                <Input
                  id="policy-reason"
                  label="Reason:"
                  value={reason}
                  onChange={(e) => { setReason(e.target.value); }}
                  placeholder="e.g. blocking known-bad stage-2 dropper from 2026-04-22 incident"
                />
                <Button type="submit" disabled={saving || !reason.trim()}>
                  {saving ? "Saving..." : "Save changes"}
                </Button>
                <Button variant="inverse" onClick={discardChanges} disabled={saving}>
                  Discard
                </Button>
              </form>
            </section>
          )}
        </>
      )}
    </>
  );
}
