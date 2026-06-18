# Web UI Specification (delta)

## MODIFIED Requirements

### Requirement: Host list is the home view

The UI SHALL render an enrolled host list as the home view of the authenticated application. The page SHALL open with a fleet-overview summary of how many hosts are online, how many are offline, and the total host count, computed from the same online/offline classification used by the rows. Each row MUST identify the host by its enrollment hostname over its full hardware identifier (falling back to the hardware identifier alone when no enrollment hostname is known), show the host's operating-system platform, show whether it is online or offline by comparing the host's last-seen timestamp to the current time, and show the host's running event count. A host MUST be classified online when its last-seen timestamp is within the last 5 minutes and offline otherwise. Activating a row MUST navigate to that host's process tree.

The change from the prior requirement is the addition of the fleet-overview summary, the enrollment hostname + full hardware identifier in the host cell, and the operating-system platform column; the online/offline classification, event count, and row-activation behavior are unchanged.

#### Scenario: Host list renders rows for enrolled hosts

- **GIVEN** the server has at least one enrolled host
- **WHEN** the operator opens the home view
- **THEN** the UI renders a row per host with the host identity, an online/offline pill, the event count, and a relative last-seen label

#### Scenario: Host list shows hostname, platform and a fleet summary

- **GIVEN** the server returns hosts with enrollment hostnames and OS versions, plus one host with no enrollment hostname
- **WHEN** the operator opens the home view
- **THEN** the UI shows a summary of online, offline, and total host counts
- **AND** each host cell shows the enrollment hostname over the full hardware identifier, the platform column shows the OS version, and a host with no enrollment hostname shows the hardware identifier alone

#### Scenario: Clicking a host opens its process tree

- **GIVEN** the host list is displayed
- **WHEN** the operator activates a host row
- **THEN** the UI navigates to the process tree page scoped to that host id
