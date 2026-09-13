import { useEffect, useState } from "react";
import {
  DetectionConfigApiError,
  getWatchedPaths,
  replaceWatchedPaths,
  type ReplaceWatchedPathsResult,
  type WatchedPath,
  type WatchedPaths as WatchedPathsResponse,
} from "../../api";
import { formatRelativeISO } from "../../time";
import { Button } from "../ui/Button";
import { Input, Select } from "../ui/Input";
import { Table, EmptyState } from "../ui/Table";
import { ReasonModal } from "./ReasonModal";

const MATCH_LABEL: Record<WatchedPath["match"], string> = {
  literal: "This file",
  prefix: "Everything under it",
};

// entryKey identifies an entry for React keys and for comparing the draft with the stored set.
function entryKey(p: WatchedPath): string {
  return `${p.match}:${p.path}`;
}

// sameEntries reports whether two sets hold the same entries in the same order, which decides whether the draft has unsaved changes.
function sameEntries(a: readonly WatchedPath[], b: readonly WatchedPath[]): boolean {
  return JSON.stringify(a.map(entryKey)) === JSON.stringify(b.map(entryKey));
}

// WatchedPaths edits the file paths every host's file-tamper sensor watches on top of the ones it always watches (issue #998). The
// operator builds a draft of the whole set and saves it with a reason; the server validates, stores and pushes it. The server is the
// one validator, and its refusal names the entry and why, so it is shown as written rather than re-derived here.
export function WatchedPaths({ canWrite }: { readonly canWrite: boolean }) {
  const [stored, setStored] = useState<WatchedPathsResponse | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [draft, setDraft] = useState<WatchedPath[]>([]);
  const [newPath, setNewPath] = useState("");
  const [newMatch, setNewMatch] = useState<WatchedPath["match"]>("prefix");
  const [reasonOpen, setReasonOpen] = useState(false);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  // conflict is set when a save was refused because someone else changed the set since it was loaded.
  const [conflict, setConflict] = useState(false);
  const [saved, setSaved] = useState<ReplaceWatchedPathsResult | null>(null);

  useEffect(() => {
    let cancelled = false;
    getWatchedPaths()
      .then((set) => {
        if (cancelled) return;
        setStored(set);
        setDraft(set.paths);
      })
      .catch((err: unknown) => {
        if (!cancelled) setLoadError(err instanceof Error ? err.message : String(err));
      });
    return () => {
      cancelled = true;
    };
  }, []);

  // loadLatest replaces the stored set and the draft with what the server holds now, after a save was refused as out of date.
  const loadLatest = () => {
    getWatchedPaths()
      .then((set) => {
        setStored(set);
        setDraft(set.paths);
        setSaveError(null);
        setConflict(false);
      })
      .catch((err: unknown) => {
        setSaveError(`The latest set could not be loaded: ${err instanceof Error ? err.message : String(err)}`);
      });
  };

  if (loadError !== null) {
    return <EmptyState>Watched paths could not be loaded: {loadError}</EmptyState>;
  }
  if (stored === null) {
    return <EmptyState>Loading watched paths...</EmptyState>;
  }

  const changed = !sameEntries(draft, stored.paths);
  const trimmed = newPath.trim();
  const canAdd =
    trimmed !== "" && draft.length < stored.max_paths && !draft.some((p) => entryKey(p) === entryKey({ path: trimmed, match: newMatch }));

  const clearOutcome = () => {
    setSaved(null);
    setSaveError(null);
    setConflict(false);
  };
  const editDraft = (next: WatchedPath[]) => {
    setDraft(next);
    clearOutcome();
  };
  const confirmSave = (reason: string) => {
    setSaving(true);
    clearOutcome();
    // The version the draft started from rides along, so a save made after someone else changed the set is refused rather than
    // silently removing what they added.
    replaceWatchedPaths(draft, reason, stored.version)
      .then((result) => {
        // Every set field comes from the response, so a label the server could not resolve does not leave the previous saver's name.
        setStored({ built_in: stored.built_in, max_paths: stored.max_paths, ...result.set });
        setSaved(result);
      })
      .catch((err: unknown) => {
        if (err instanceof DetectionConfigApiError && err.code === "detection_config.conflict") {
          setConflict(true);
          setSaveError(
            "Not saved: someone changed the watched paths after this page loaded them. Load the latest set to see their change, then make yours again.",
          );
          return;
        }
        setSaveError(`Not saved: ${err instanceof Error ? err.message : String(err)}`);
      })
      .finally(() => {
        setSaving(false);
        setReasonOpen(false);
      });
  };

  return (
    <>
      <p className="detection-config__note">
        Each host&apos;s file sensor records writes, renames, truncations and deletions of these paths, on top of the ones it always
        watches: {stored.built_in.map((p) => p.path).join(", ")}. Keep a prefix narrow, because every write under a watched directory is
        sent to the server. A saved change reaches online hosts within seconds, and hosts that are offline or enroll later within minutes of
        connecting.
      </p>

      {draft.length === 0 ? (
        <EmptyState>No paths added. Hosts watch only the paths they always watch.</EmptyState>
      ) : (
        <Table>
          <thead>
            <tr>
              <th>Path</th>
              <th>Covers</th>
              {canWrite && <th aria-label="Actions" />}
            </tr>
          </thead>
          <tbody>
            {draft.map((p, i) => (
              <tr key={entryKey(p)}>
                <td>
                  <code>{p.path}</code>
                </td>
                <td>{MATCH_LABEL[p.match]}</td>
                {canWrite && (
                  <td>
                    <Button
                      variant="text-link"
                      aria-label={`Remove ${p.path}`}
                      disabled={saving}
                      onClick={() => {
                        editDraft(draft.filter((_, j) => j !== i));
                      }}
                    >
                      Remove
                    </Button>
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </Table>
      )}
      <p className="detection-config__note">
        {draft.length} of {stored.max_paths} paths.
        {stored.updated_at !== undefined &&
          ` Last saved ${formatRelativeISO(stored.updated_at)} by ${stored.updated_by_label ?? stored.updated_by ?? ""}.`}
      </p>

      {canWrite && (
        <div className="detection-config__form">
          <div className="detection-config__form-field--full">
            <Input
              label="Path"
              id="dc-watched-path"
              value={newPath}
              disabled={saving}
              placeholder="/Library/StartupItems/"
              onChange={(e) => {
                setNewPath(e.target.value);
              }}
            />
          </div>
          <Select
            label="Covers"
            id="dc-watched-match"
            inline={false}
            value={newMatch}
            disabled={saving}
            onChange={(e) => {
              setNewMatch(e.target.value === "literal" ? "literal" : "prefix");
            }}
          >
            <option value="prefix">{MATCH_LABEL.prefix} (end the path with /)</option>
            <option value="literal">{MATCH_LABEL.literal}</option>
          </Select>
          <div className="detection-config__form-actions">
            <Button
              variant="inverse"
              disabled={!canAdd || saving}
              onClick={() => {
                editDraft([...draft, { path: trimmed, match: newMatch }]);
                setNewPath("");
              }}
            >
              Add path
            </Button>
            <Button
              variant="inverse"
              disabled={!changed || saving}
              onClick={() => {
                editDraft(stored.paths);
              }}
            >
              Discard changes
            </Button>
            <Button
              disabled={!changed || saving}
              onClick={() => {
                setReasonOpen(true);
              }}
            >
              Save and push to hosts
            </Button>
          </div>
        </div>
      )}
      {saveError !== null && (
        <div className="detection-config__error" role="alert">
          {saveError}
          {conflict && (
            <Button variant="text-link" onClick={loadLatest}>
              Load the latest set (discards your changes)
            </Button>
          )}
        </div>
      )}
      {saved !== null && <SavedNotice result={saved} />}
      {reasonOpen && (
        <ReasonModal
          title="Save watched paths?"
          description="The set replaces the current one on every enrolled host. The change is recorded in the audit log with this reason."
          confirmLabel="Save"
          busy={saving}
          placeholder="Why these paths are watched"
          onConfirm={confirmSave}
          onCancel={() => {
            setReasonOpen(false);
          }}
        />
      )}
    </>
  );
}

// SavedNotice says how far a saved set's push reached. A push skipped because the host list could not be read is called out, since
// "sent to 0 hosts" would read as a deployment with no hosts.
function SavedNotice({ result }: { readonly result: ReplaceWatchedPathsResult }) {
  if (result.fanout_skipped_reason !== undefined) {
    return (
      <div className="detection-config__error" role="alert">
        Saved as version {result.set.version}, but not sent: the enrolled hosts could not be listed. Hosts receive the set within minutes
        once they can be.
      </div>
    );
  }
  const queued = result.fanout_hosts - result.fanout_failed;
  return (
    <p className="detection-config__note" role="status">
      Saved as version {result.set.version}. Queued for {queued} of {result.fanout_hosts} enrolled{" "}
      {result.fanout_hosts === 1 ? "host" : "hosts"}
      {result.fanout_failed > 0 ? "; the rest receive it within minutes." : "."}
    </p>
  );
}
