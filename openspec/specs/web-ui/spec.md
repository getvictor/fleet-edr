# Web UI Specification

## Purpose

The web UI is the analyst- and operator-facing surface of the Fleet EDR product. It is where a SOC analyst triages alerts, investigates a process and its network/DNS activity, kills a running process on a host, and where an admin manages the server-driven blocklist policy and reviews the deployed detection content. It is the visible product to anyone who is not an agent or a backend integration: every operator task documented in the MVP plan happens here.

This specification fixes the user-observable behaviour of each page: what an analyst can see and do, how navigation flows between pages, and how authentication boundaries are presented. The product behaviour can then be validated against the spec without reading the React source.

## Requirements

### Requirement: Authenticated entry to the application

The UI SHALL probe the server's session endpoint on application load and SHALL render the login page when the probe indicates no active session. A successful login MUST establish a session and route the user to the application's home view; an invalid login MUST surface a generic error without revealing whether the email or the password was wrong. When the session lapses while the app is already open (an idle or absolute timeout, or a server-side revocation) and any subsequent request to the server is rejected as unauthenticated, the UI MUST return the operator to the login page rather than leaving them on a page that renders a raw transport error such as `API error: 401`. The redirect SHALL preserve the operator's current location so a successful re-login returns them to where they were.

#### Scenario: Anonymous user lands on the login page

- **GIVEN** a browser with no active session cookie
- **WHEN** the user navigates to the application
- **THEN** the UI renders the login page with the configured sign-in controls (SSO and a break-glass entry point)

#### Scenario: Successful login routes to the home view

- **GIVEN** the login page is displayed
- **WHEN** the user submits a valid email and password
- **THEN** the server establishes a session and the UI re-renders into the host list as the home view

#### Scenario: Failed login shows a non-enumerating error

- **GIVEN** the login page is displayed
- **WHEN** the user submits credentials the server rejects
- **THEN** the UI shows a single generic error such as "invalid email or password"
- **AND** the UI does not distinguish between unknown email and wrong password

#### Scenario: Mid-session expiry returns the operator to login

- **GIVEN** an authenticated operator viewing any page after the load-time session probe has already succeeded
- **WHEN** a subsequent request to the server is rejected as unauthenticated because the session has expired or been revoked
- **THEN** the UI returns the operator to the login page rather than rendering a raw `API error: 401` on the current page
- **AND** the operator's current location is preserved so a successful re-login returns them to where they were

### Requirement: Logout terminates the session

The UI SHALL expose a logout control that, when invoked, requests the server to terminate the active session and returns the user to the login page. After logout, subsequent protected requests MUST receive `401` and the UI MUST render the login page in response.

#### Scenario: Operator logs out

- **GIVEN** an authenticated operator viewing any page
- **WHEN** the operator activates the logout control
- **THEN** the UI requests session termination and re-renders the login page

### Requirement: Host list is the home view

The UI SHALL render an enrolled host list as the home view of the authenticated application. Each row MUST identify the host, show whether it is online or offline by comparing the host's last-seen timestamp to the current time, and show the host's running event count. A host MUST be classified online when its last-seen timestamp is within the last 5 minutes and offline otherwise. Activating a row MUST navigate to that host's process tree.

#### Scenario: Host list renders rows for enrolled hosts

- **GIVEN** the server has at least one enrolled host
- **WHEN** an authenticated operator opens the home view
- **THEN** the UI renders a row per host with the host id, an online/offline pill, the event count, and a relative last-seen label

#### Scenario: Clicking a host opens its process tree

- **GIVEN** the host list is displayed
- **WHEN** the operator activates a host row
- **THEN** the UI navigates to the process tree page scoped to that host id

### Requirement: Process tree visualization

The UI SHALL render the process tree page for a host as a hierarchical visualization in which each node represents a process and edges represent parent-child fork/exec relationships. Activating a process node MUST open a side panel that displays the process's investigation detail. The page MUST support panning, zooming, and a search affordance that jumps the viewport to matching nodes.

#### Scenario: Process tree renders for a host

- **GIVEN** the operator opens a host's process tree page
- **WHEN** the page loads
- **THEN** the UI renders a hierarchical tree of the host's processes for the selected time window

#### Scenario: Selecting a process opens the detail panel

- **GIVEN** the process tree is displayed
- **WHEN** the operator activates a process node
- **THEN** the UI opens a side panel showing that process's detail

### Requirement: Process detail content

The process detail panel SHALL render, for the selected process: the path, the argument vector, the UID, the GID, the SHA-256 hash, the code-signing identity, the network connections attributed to the process, the DNS queries attributed to the process, and the re-exec chain (the prior process generations that led to the current image). The panel MUST expose a "Kill process" control that issues a kill command targeting the selected PID.

#### Scenario: Process detail surfaces investigation fields

- **GIVEN** the operator selects a process
- **WHEN** the detail panel renders
- **THEN** the panel shows the path, args, UID, GID, SHA-256, code-signing identity, attributed network connections, attributed DNS queries, and the re-exec chain (when present)

#### Scenario: Operator kills a running process

- **GIVEN** the process detail panel is displayed for a process that has not exited
- **WHEN** the operator activates the kill control
- **THEN** the UI issues a kill command for that PID and reflects the command's lifecycle state (pending, completed, or failed)

### Requirement: Alert list filtering and lifecycle controls

The UI SHALL provide an alert list page that defaults to open alerts, supports filtering by status and by severity, and shows each alert's severity badge and MITRE technique tags. Each row MUST expose lifecycle controls that allow the operator to acknowledge, resolve, and reopen an alert; the affected row's status MUST update on success.

#### Scenario: Default view shows only open alerts

- **GIVEN** the operator opens the alert list
- **WHEN** the page first renders
- **THEN** only alerts whose status is `open` are visible

#### Scenario: Operator changes the status filter

- **GIVEN** the alert list is displayed
- **WHEN** the operator selects a different status filter (e.g. `acknowledged`, `resolved`, or all)
- **THEN** the visible rows refresh to match the new filter

#### Scenario: Operator acknowledges an open alert

- **GIVEN** an open alert is visible
- **WHEN** the operator activates the acknowledge control
- **THEN** the alert's status transitions to `acknowledged` and the row reflects the new status

### Requirement: Alert pivots to the host process tree

The UI SHALL provide a control on each alert in the list that pivots into the alerted host's process tree page anchored at the moment the alert fired. The receiving page MUST present the alert's metadata (severity, title, time) as a breadcrumb and MUST default the time window to one wide enough to display historical alerts.

#### Scenario: Operator pivots from an alert to the host context

- **GIVEN** an alert is visible in the alert list
- **WHEN** the operator activates the alert's primary link
- **THEN** the UI navigates to the host's process tree pinned to the alert's time
- **AND** the receiving page renders an alert breadcrumb identifying severity, title, and time

### Requirement: Policy editor with audit reason gate

The UI SHALL provide a policy editor that loads the current blocklist, lets the operator stage additions and removals to paths and SHA-256 hashes, and persists the staged copy to the server only when the operator submits a non-empty audit reason. The editor MUST validate paths as absolute and hashes as 64-character lowercase hex before allowing them to be staged. Saving MUST issue the documented admin policy update request with the operator's identity recorded as the actor.

#### Scenario: Operator stages and saves a policy change

- **GIVEN** the policy editor is loaded with the current policy
- **WHEN** the operator stages one or more changes and submits a non-empty reason
- **THEN** the UI issues a policy update request carrying the new paths, hashes, the operator's identity, and the reason
- **AND** on success the editor reflects the new persisted version

#### Scenario: Save is blocked without a reason

- **GIVEN** the operator has staged changes
- **WHEN** the operator attempts to save without entering a reason
- **THEN** the editor refuses to save and surfaces a visible error explaining the reason is required

#### Scenario: Invalid path or hash is rejected at staging

- **GIVEN** the operator types a non-absolute path or a hash that is not 64 lowercase hex characters
- **WHEN** the operator attempts to stage the entry
- **THEN** the editor refuses to add it and surfaces a visible validation error

### Requirement: ATT&CK coverage page

The UI SHALL provide a coverage page that renders the rule-to-technique mapping in the same shape the upstream MITRE ATT&CK Navigator uses, grouped by tactic. Each covered technique MUST link to its upstream MITRE reference, and the rule identifiers that cover a technique MUST link to that rule's documentation page. The page MUST also expose a control to download the underlying Navigator layer JSON.

#### Scenario: Coverage page renders technique groups

- **GIVEN** the server reports at least one covered technique
- **WHEN** the operator opens the coverage page
- **THEN** the UI renders technique rows grouped by ATT&CK tactic
- **AND** each technique id links to its upstream MITRE page
- **AND** each covering rule id links to that rule's documentation page

#### Scenario: Operator exports the Navigator layer

- **GIVEN** the coverage page is displayed
- **WHEN** the operator activates the export control
- **THEN** the browser downloads the Navigator layer JSON for the current coverage

### Requirement: Per-rule documentation page

The UI SHALL provide a rule documentation page reachable by rule id from the coverage page and from the alert breadcrumb. The page MUST render the rule's title, summary, severity, ATT&CK technique mapping, event types, description, configuration knobs when present, false-positive sources when present, and limitations when present. An unknown rule id MUST land on an empty state pointing back to the coverage page rather than producing a hard error.

#### Scenario: Rule detail renders documented fields

- **GIVEN** a registered rule with documentation
- **WHEN** the operator navigates to that rule's detail page
- **THEN** the UI renders the rule's title, summary, severity, ATT&CK techniques, event types, and description
- **AND** when the rule declares config knobs, false positives, or limitations, those sections render

#### Scenario: Unknown rule id renders a navigable empty state

- **GIVEN** a rule id that the server does not know about
- **WHEN** the operator navigates to that rule's detail page
- **THEN** the UI renders an empty state that links back to the ATT&CK coverage page

### Requirement: Navigation and action affordances are capability-gated

The UI SHALL hide navigation entries and action controls that the authenticated operator's effective permission set (obtained from the session probe) does not authorize, so an operator is not shown affordances they cannot use. A navigation entry SHALL be hidden when the permission set does not contain the read action that gates its destination surface. An action control SHALL be hidden when the permission set does not contain the action that the control performs. Gating SHALL be derived solely from the server-provided permission set; the UI SHALL NOT contain its own mapping from role names to permitted actions. Hiding an affordance is a usability measure only and SHALL NOT be relied upon as access control; the server remains authoritative for every action.

#### Scenario: Application control entry hidden without read access

- **GIVEN** an operator whose permission set does not contain `application_control.read`
- **WHEN** the authenticated application renders its navigation
- **THEN** the Application control navigation entry is not shown
- **AND** navigating directly to the Application control route does not present the surface

#### Scenario: Application control entry shown with read access

- **GIVEN** an operator whose permission set contains `application_control.read`
- **WHEN** the navigation renders
- **THEN** the Application control navigation entry is shown

#### Scenario: Kill process control hidden without the action

- **GIVEN** an operator whose permission set does not contain `host.kill_process`
- **WHEN** the operator opens a process's detail
- **THEN** the Kill process control is not rendered

#### Scenario: Kill process control shown with the action

- **GIVEN** an operator whose permission set contains `host.kill_process`
- **WHEN** the operator opens a process's detail
- **THEN** the Kill process control is rendered and can be invoked

### Requirement: Authorization denials degrade gracefully

The UI SHALL present an authorization denial as a clear, human-readable no-access state and SHALL NOT surface a raw transport error such as `API error: 403`. When the server denies a request the UI believed was permitted (for example because the operator's role changed after the session permission set was fetched), the UI SHALL render the no-access state for that surface or action AND SHALL refresh the permission set from the session endpoint so subsequent rendering reflects the operator's current permissions. The refetch SHALL be deduplicated and throttled so that multiple gated components failing at once, or repeated denials in quick succession, collapse to a single in-flight request rather than a storm of session-endpoint calls. When the permission set is unavailable (for example an older server that does not return one), the UI MAY render affordances optimistically but MUST still degrade any resulting denial gracefully, so an absent permission set can never grant access; only the server can.

#### Scenario: Deep-link to a gated surface shows a no-access state

- **GIVEN** an operator whose permission set does not contain `application_control.read`
- **WHEN** the operator navigates directly to the Application control route
- **THEN** the UI shows a no-access message indicating the operator lacks access to that surface
- **AND** the UI does not display a raw `API error: 403`

#### Scenario: Mid-session revocation degrades and refetches

- **GIVEN** an operator who held an action and whose role binding was revoked after their session permission set was fetched
- **WHEN** the operator invokes the affected action and the server responds 403
- **THEN** the UI renders the no-access state for that action
- **AND** the UI refetches the session permission set so the corresponding affordance is hidden on subsequent renders

#### Scenario: Simultaneous denials collapse to one refetch

- **GIVEN** an operator whose role was revoked mid-session and a page that renders several gated affordances at once
- **WHEN** multiple of those affordances trigger an authorization denial in quick succession
- **THEN** the UI issues at most one in-flight refetch of the session permission set rather than one per denial
- **AND** subsequent renders reflect the refreshed permission set
