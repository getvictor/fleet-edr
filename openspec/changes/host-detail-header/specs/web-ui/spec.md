## ADDED Requirements

### Requirement: Host detail header

The host detail page SHALL open with an identity header: the enrollment hostname as the page title (falling back to the host identifier when no hostname is known), an online/offline indicator derived from the host's last-seen time using the same 5-minute classification as the host list, and a meta row carrying the OS identity (product name, version, and build), the agent version, the last-seen time, the source IP, the event count, and the enrollment date. The raw host identifier SHALL remain visible and copyable in one click for correlation with server logs. The header MUST load best-effort: a failed detail fetch degrades to the host identifier as the title and MUST NOT block the process tree from rendering.

#### Scenario: Header shows identity for an enrolled host

- **GIVEN** an enrolled host with a fresh inventory check-in
- **WHEN** the operator opens the host's detail page
- **THEN** the title is the enrollment hostname and the meta row shows the OS identity, agent version, last seen, source IP, event count, and enrollment date
- **AND** the raw host identifier is visible and copyable

#### Scenario: Header degrades when the detail fetch fails

- **GIVEN** the host detail endpoint returns an error
- **WHEN** the operator opens the host's detail page
- **THEN** the title falls back to the host identifier
- **AND** the process tree still renders
