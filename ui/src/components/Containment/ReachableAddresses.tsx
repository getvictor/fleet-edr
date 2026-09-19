import { useCallback, useEffect, useState } from "react";
import { getReachableAddresses, listContainment, ReachableSetConflictError, replaceReachableAddresses } from "../../api";
import { containmentPhase, type ContainmentPhase } from "../../containment";
import { useReauthRetry } from "../../hooks/useReauthRetry";
import { useCan, PermissionAction } from "../../permissions-core";
import type { ReachableAddress, ReachableSet } from "../../types";
import { formatRelativeISO } from "../../time";
import { ReauthModal } from "../ReauthModal";
import { Button } from "../ui/Button";
import { Input, Select } from "../ui/Input";
import { PageHeader } from "../ui/PageHeader";
import { Table, EmptyState } from "../ui/Table";
import { ReasonModal } from "../DetectionConfig/ReasonModal";
import "./ReachableAddresses.scss";

// MAX_ADDRESSES mirrors api.MaxReachableAddresses. Held here only to stop the operator building a draft the server is certain to
// refuse; the server remains the one validator and its refusal is what gets shown.
const MAX_ADDRESSES = 64;

// MAX_PORT is the highest port an entry may name, mirroring the server's own bound.
const MAX_PORT = 65535;

// CONTAINED_INTENT is the set of phases in which a host is meant to be contained, so the reachable set is what stands between it and
// the network. "containing" and "contain_failed" are in it because containment was asked for in both: one is on its way, and the
// other is a host the operator still has to deal with. Excluding them would under-report who a change reaches.
const CONTAINED_INTENT: readonly ContainmentPhase[] = ["containing", "contained", "contain_failed"];

// destinationKey identifies a destination for React keys and for the repeat check, matching what the server calls a duplicate:
// address, port and transport, with the note excluded. Two entries for one destination under different names are one filter rule,
// and the server refuses the pair rather than silently keeping one operator's name over another's.
//
// It compares addresses AS WRITTEN, while the server compares them canonical (it stores "192.0.2.7" as "192.0.2.7/32"). So this
// catches the plain repeat and leaves the same destination spelled two ways to the server, which names the entry in its refusal.
function destinationKey(a: ReachableAddress): string {
  return `${a.cidr.trim().toLowerCase()}|${String(a.port ?? 0)}|${a.transport ?? ""}`;
}

// sameEntries reports whether two sets hold the same entries in the same order, which decides whether the draft has unsaved changes.
// The note is part of this comparison though not of destinationKey: renaming an entry is an edit worth saving, just not a duplicate.
function sameEntries(a: readonly ReachableAddress[], b: readonly ReachableAddress[]): boolean {
  const shape = (e: ReachableAddress) => `${destinationKey(e)}|${e.note ?? ""}`;
  return JSON.stringify(a.map(shape)) === JSON.stringify(b.map(shape));
}

// describeAllows says what an entry narrows the destination to, in the terms the form offers.
function describeAllows(a: ReachableAddress): string {
  const port = a.port === undefined || a.port === 0 ? "Any port" : `Port ${String(a.port)}`;
  // The server omits transport for an entry that allows both, so undefined is the only spelling of "both" that reaches the client.
  return `${port}, ${a.transport === undefined ? "TCP and UDP" : a.transport.toUpperCase()}`;
}

// ReachableAddresses edits the destinations a contained host may still reach, on top of the lifeline containment keeps for itself
// (issue #1059). The operator builds a draft of the whole set and saves it with a reason, the shape the watched-path set already
// uses: the set is versioned and delivered whole, so a partial edit is not something the API can express.
//
// Two departures from that page are deliberate. Saving goes through useReauthRetry, because widening this set weakens every
// containment in force rather than changing what one host reports, and the server gates the write on a recent sign-in. And the page
// says how many hosts are contained as it is edited, because "who does this reach" is the question being asked when an operator
// widens or revokes during an incident, and a settings form that cannot answer it sends them to another tab to find out.
export function ReachableAddresses() {
  // Read opens the page; write enables the edit controls. The server chokepoint remains the authority (ADR-0012), so hiding the
  // controls is about not offering an operator an action that would be refused, not about enforcing anything.
  const canWrite = useCan()(PermissionAction.ContainmentConfigWrite);
  const [stored, setStored] = useState<ReachableSet | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [draft, setDraft] = useState<ReachableAddress[]>([]);
  const [newCidr, setNewCidr] = useState("");
  const [newPort, setNewPort] = useState("");
  const [newTransport, setNewTransport] = useState<"" | "tcp" | "udp">("");
  const [newNote, setNewNote] = useState("");
  const [reasonOpen, setReasonOpen] = useState(false);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  // conflict is set when a save was refused because someone else changed the set since it was loaded.
  const [conflict, setConflict] = useState(false);
  const [savedVersion, setSavedVersion] = useState<number | null>(null);
  // contained is how many hosts the set reaches at this moment, or null while it is unknown. A failed read leaves the count unsaid
  // rather than failing the page: the count is context for the edit, and not knowing it is a poor reason to refuse the edit.
  const [contained, setContained] = useState<number | null>(null);

  const replace = useCallback(
    async (addresses: ReachableAddress[], reason: string, expectedVersion: number) =>
      replaceReachableAddresses(addresses, reason, expectedVersion),
    [],
  );
  const { call: callReplace, modal: reauthModal } = useReauthRetry(replace);

  useEffect(() => {
    let cancelled = false;
    getReachableAddresses()
      .then((set) => {
        if (cancelled) return;
        setStored(set);
        setDraft(set.addresses);
      })
      .catch((err: unknown) => {
        if (!cancelled) setLoadError(err instanceof Error ? err.message : String(err));
      });
    listContainment()
      .then((states) => {
        if (cancelled) return;
        setContained(states.filter((s) => CONTAINED_INTENT.includes(containmentPhase(s) as ContainmentPhase)).length);
      })
      .catch(() => {
        // Deliberately unreported: the page's subject is the set, and the count rides along.
      });
    return () => {
      cancelled = true;
    };
  }, []);

  // loadLatest replaces the stored set and the draft with what the server holds now, after a save was refused as out of date.
  const loadLatest = () => {
    getReachableAddresses()
      .then((set) => {
        setStored(set);
        setDraft(set.addresses);
        setSaveError(null);
        setConflict(false);
      })
      .catch((err: unknown) => {
        setSaveError(`The latest destinations could not be loaded: ${err instanceof Error ? err.message : String(err)}`);
      });
  };

  if (loadError !== null) {
    return <EmptyState>Reachable destinations could not be loaded: {loadError}</EmptyState>;
  }
  if (stored === null) {
    return <EmptyState>Loading reachable destinations...</EmptyState>;
  }

  const changed = !sameEntries(draft, stored.addresses);
  // An empty port box means every port, which the wire spells as an absent port. Anything else has to be a port number, and a
  // half-typed one leaves Add disabled rather than sending the server something it will refuse.
  const port = newPort.trim() === "" ? undefined : Number(newPort);
  const portUsable = port === undefined || (Number.isInteger(port) && port >= 1 && port <= MAX_PORT);
  const candidate: ReachableAddress = {
    cidr: newCidr.trim(),
    ...(port === undefined ? {} : { port }),
    ...(newTransport === "" ? {} : { transport: newTransport }),
    ...(newNote.trim() === "" ? {} : { note: newNote.trim() }),
  };
  const canAdd =
    newCidr.trim() !== "" && portUsable && draft.length < MAX_ADDRESSES && !draft.some((a) => destinationKey(a) === destinationKey(candidate));

  const clearOutcome = () => {
    setSavedVersion(null);
    setSaveError(null);
    setConflict(false);
  };
  const editDraft = (next: ReachableAddress[]) => {
    setDraft(next);
    clearOutcome();
  };
  const confirmSave = (reason: string) => {
    setSaving(true);
    clearOutcome();
    // The version the draft started from rides along, so a save made after someone else changed the set is refused rather than
    // silently dropping the destination they added.
    callReplace(draft, reason, stored.version)
      .then((set) => {
        setStored(set);
        setDraft(set.addresses);
        setSavedVersion(set.version);
        setReasonOpen(false);
      })
      .catch((err: unknown) => {
        if (err instanceof ReachableSetConflictError) {
          setConflict(true);
        }
        setSaveError(`Not saved: ${err instanceof Error ? err.message : String(err)}`);
      })
      .finally(() => {
        setSaving(false);
      });
  };

  return (
    <section className="reachable">
      <PageHeader title="Reachable destinations" />
      <p className="reachable__note">
        A contained host reaches the EDR server and what it needs to find it, and nothing else. Destinations listed here are reachable
        on top of that, from every contained host. Keep the list to the systems a responder needs, because each entry is a hole in
        every containment in force.
      </p>
      <p className="reachable__note" role="status">
        {contained === null
          ? "How many hosts this reaches could not be read."
          : `${String(contained)} ${contained === 1 ? "host is" : "hosts are"} contained or being contained right now.`}
      </p>

      {draft.length === 0 ? (
        <EmptyState>No destinations added. A contained host reaches only the EDR server.</EmptyState>
      ) : (
        <Table>
          <thead>
            <tr>
              <th>Destination</th>
              <th>Allows</th>
              <th>Name</th>
              {canWrite && <th aria-label="Actions" />}
            </tr>
          </thead>
          <tbody>
            {draft.map((a, i) => (
              <tr key={destinationKey(a)}>
                <td>
                  <code>{a.cidr}</code>
                </td>
                <td>{describeAllows(a)}</td>
                <td>{a.note ?? ""}</td>
                {canWrite && (
                  <td>
                    <Button
                      variant="text-link"
                      aria-label={`Remove ${a.cidr}`}
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
      <p className="reachable__note">
        {draft.length} of {MAX_ADDRESSES} destinations.
        {stored.updated_at !== undefined && ` Last saved ${formatRelativeISO(stored.updated_at)} by ${stored.updated_by ?? ""}.`}
      </p>

      {canWrite && (
      <div className="reachable__form">
        <div className="reachable__form-field--full">
          <Input
            label="Destination"
            id="reachable-cidr"
            value={newCidr}
            disabled={saving}
            placeholder="198.51.100.7 or 10.0.0.0/8"
            onChange={(e) => {
              setNewCidr(e.target.value);
            }}
          />
        </div>
        <Input
          label="Port"
          id="reachable-port"
          value={newPort}
          disabled={saving}
          placeholder="Any port"
          onChange={(e) => {
            setNewPort(e.target.value);
          }}
        />
        <Select
          label="Transport"
          id="reachable-transport"
          inline={false}
          value={newTransport}
          disabled={saving}
          onChange={(e) => {
            setNewTransport(e.target.value === "tcp" ? "tcp" : e.target.value === "udp" ? "udp" : "");
          }}
        >
          <option value="">TCP and UDP</option>
          <option value="tcp">TCP</option>
          <option value="udp">UDP</option>
        </Select>
        <div className="reachable__form-field--full">
          <Input
            label="Name"
            id="reachable-note"
            value={newNote}
            disabled={saving}
            placeholder="MDM server"
            onChange={(e) => {
              setNewNote(e.target.value);
            }}
          />
        </div>
        {!portUsable && (
          <p className="reachable__form-field--full reachable__hint" role="alert">
            A port must be a number between 1 and 65535, or left empty for every port.
          </p>
        )}
        <div className="reachable__form-actions">
          <Button
            variant="inverse"
            disabled={!canAdd || saving}
            onClick={() => {
              editDraft([...draft, candidate]);
              setNewCidr("");
              setNewPort("");
              setNewTransport("");
              setNewNote("");
            }}
          >
            Add destination
          </Button>
          <Button
            variant="inverse"
            disabled={!changed || saving}
            onClick={() => {
              editDraft(stored.addresses);
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
        <div className="reachable__error" role="alert">
          {saveError}
          {conflict && (
            <Button variant="text-link" onClick={loadLatest}>
              Load the latest destinations (discards your changes)
            </Button>
          )}
        </div>
      )}
      {savedVersion !== null && (
        <p className="reachable__note" role="status">
          Saved as version {savedVersion}. A host contained from now on gets it with its containment; a host already contained gets it
          within minutes.
        </p>
      )}
      {reasonOpen && (
        <ReasonModal
          title="Save reachable destinations?"
          description="Every contained host, now and later, can reach these. The change is recorded in the audit log with this reason."
          confirmLabel="Save"
          busy={saving}
          placeholder="Why these destinations stay reachable"
          onConfirm={confirmSave}
          onCancel={() => {
            setReasonOpen(false);
          }}
        />
      )}
      <ReauthModal {...reauthModal} />
    </section>
  );
}
