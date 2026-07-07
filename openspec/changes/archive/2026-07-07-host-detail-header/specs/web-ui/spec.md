## ADDED Requirements

### Requirement: Host detail header

The host detail page SHALL open with an identity header leading with the enrollment hostname as the page title (falling back to the host identifier when no hostname is known) and an online/offline indicator derived from the host's last-seen time using the same 5-minute classification as the host list. The always-visible meta row SHALL carry the OS identity (product name, version, and build) and, only while the host is offline, the last-seen time; when the host is online the indicator already conveys liveness so the last-seen segment SHALL be omitted. The remaining reference facts (the raw host identifier with a one-click copy control, the agent version, the source IP, the event count, the exact last-seen time, and the enrollment date) SHALL be presented in a details disclosure opened from the header rather than inline, so the header stays focused on identity and status; the copy control SHALL sit with the labeled host identifier inside the disclosure, not beside the hostname. The header MUST load best-effort: a failed detail fetch degrades to the host identifier as the title and MUST NOT block the process tree from rendering.

#### Scenario: Header shows identity for an enrolled host

- **GIVEN** an enrolled host with a fresh inventory check-in that is currently online
- **WHEN** the operator opens the host's detail page
- **THEN** the title is the enrollment hostname, the online indicator is shown, and the meta row shows the OS identity
- **AND** the last-seen time is not shown in the meta row because the host is online
- **AND** the agent version, source IP, event count, enrollment date, and the raw host identifier with its copy control are available in the header's details disclosure rather than inline

#### Scenario: Header degrades when the detail fetch fails

- **GIVEN** the host detail endpoint returns an error
- **WHEN** the operator opens the host's detail page
- **THEN** the title falls back to the host identifier
- **AND** the process tree still renders
