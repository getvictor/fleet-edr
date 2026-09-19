# Operators edit the reachable destinations in the console

Issue #1059. The set change gave the reachable-address set its storage, validation and API, and the delivery change put it on every contained host's command and kept it there through the extension's restarts. Choosing which destinations stay reachable still took a hand-written API call, which is the wrong thing to ask of a responder who is containing a host during an incident. This change adds the editor to admin settings.

## What changes

- **A Containment section in admin settings.** It lists the stored set, says how many of the allowed destinations are used, and shows when and by whom the set was last saved.
- **What the change reaches, on the page that makes it.** The section reports how many hosts are contained or being contained, read from `GET /api/containment`. Widening or revoking this set changes what every one of those hosts can talk to, and an operator deciding whether to do it during an incident should not have to open another tab to find out how many that is. The count is context rather than the subject, so a containment list the server will not serve leaves the count unsaid and the editor working.
- **Editing a draft of the whole set.** An operator with `containment_config.write` adds a destination as an address or CIDR range, optionally narrowed to one port and one transport, names it, removes entries, and can discard the draft. Saving asks for a reason and sends the whole set with `PUT /api/v1/containment/reachable-addresses`.
- **Reauthentication, because this write is gated on it.** `containment_config.write` is in the rego's `requires_fresh_auth` set: widening the reachable set weakens every containment in force, rather than changing what one host reports. The save goes through the same `useReauthRetry` the other fresh-auth actions use, so the operator is prompted once and the save is retried.
- **The server stays the one validator.** The editor refuses only what it can see without restating server rules: an empty destination, a port that is not a port, a destination already in the draft as written, and a draft at the size bound. Every other refusal is shown with the server's own message, which names the entry, alongside a sentence saying which rule it broke, with the draft kept so the operator can fix it.
- **No lost updates.** The editor sends the version its draft started from as `expected_version`, and a set someone else changed in the meantime is refused, the draft kept, and the latest offered.
- **The host page says a contained host is not fully cut off.** A responder reading "Contained" can reasonably take it to mean the host has no network. When the set holds destinations, the host's page says how many it can still reach and where to change them, next to the badge that already says when its name filtering is not in force. Both are reasons the host still has some network, so neither hides the other, and an empty set says nothing at all so a host that reads as fully cut off is one that is.
- **Readers see, and do not edit.** Without `containment_config.write` the section shows the set with no editing controls.

## Out of scope

- Which version of the set each host has applied. The agent reports it and the server converges on it; surfacing it per host is a later change.
- Naming a destination by hostname rather than address. The set is delivered to a filter that matches on addresses, so a name would have to be resolved somewhere, and where is a question of its own.
- Scoping the set to host groups.
