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
- **THEN** the server establishes a session and the UI re-renders into the alert list as the home view

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

### Requirement: Process tree visualization

The UI SHALL render the process tree page for a host as a hierarchical visualization in which each node represents a process and edges represent parent-child fork/exec relationships. Activating a process node MUST open a side panel that displays the process's investigation detail. The page MUST support panning, zooming, and a search affordance that jumps the viewport to matching nodes. When the server collapses repeated identical-path siblings into an aggregated node, the UI MUST render that node as a group badge showing the member count (a "×N" affordance) rather than as a single process, and activating the aggregated node MUST expand it in place to reveal the sample of underlying members rather than opening the process detail panel; a member surfaced by that expansion behaves as an ordinary process node. Expanding an aggregated node in place is the affordance for inspecting its members; the page does not carry a separate global flatten control.

#### Scenario: Process tree renders for a host

- **GIVEN** the operator opens a host's process tree page
- **WHEN** the process data loads
- **THEN** the UI renders a hierarchical tree of the host's processes for the selected time window

#### Scenario: Selecting a process opens the detail panel

- **GIVEN** the process tree is displayed
- **WHEN** the operator activates a process node
- **THEN** the UI opens a side panel showing that process's detail

#### Scenario: Repeated siblings render as an aggregated badge

- **GIVEN** a host whose process forest contains a group of repeated identical-path siblings the server collapsed into an aggregated node
- **WHEN** the process tree renders
- **THEN** that group appears as a single node with a "×N" count badge and its individual members are not shown
- **AND** activating the aggregated node expands it in place to reveal the sample of underlying members

### Requirement: Process detail content

The process detail panel SHALL render, for the selected process: the path, the argument vector, the UID, the GID, the SHA-256 hash, the code-signing verdict together with the signing identity and team identifier (the verdict only for a process that has exec'd, mirroring the tree's fork-only rule), the network connections attributed to the process, the DNS queries attributed to the process, and the re-exec chain (the prior process generations that led to the current image). The command line, path, SHA-256 hash, cdhash (when present), signing identity, and team identifier MUST each be copyable in one click. The panel MUST expose a "Kill process" control that issues a kill command targeting the selected PID.

#### Scenario: Process detail surfaces investigation fields

- **GIVEN** the operator selects a process
- **WHEN** the detail panel renders
- **THEN** the panel shows the path, args, UID, GID, SHA-256, the code-signing verdict with signing identity and team identifier, attributed network connections, attributed DNS queries, and the re-exec chain (when present)

#### Scenario: Evidence fields copy in one click

- **GIVEN** the detail panel is displayed for a signed process
- **WHEN** the operator activates a copy control
- **THEN** the corresponding value (command line, path, SHA-256, cdhash, signing identity, or team identifier) is copied to the clipboard

#### Scenario: Verdict distinguishes the signer categories

- **GIVEN** processes signed as Apple platform, Developer ID, ad-hoc, and one reporting no code-signing block
- **WHEN** each process's detail panel renders
- **THEN** the verdicts read Apple platform, Developer ID with the team identifier, ad-hoc, and unsigned respectively

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

The UI SHALL provide a control on each alert in the list that pivots into the alerted host's process tree page anchored at the moment the alert fired. The receiving page MUST present the alert's metadata (severity, title, time) as a breadcrumb and MUST default the time window to one wide enough to display historical alerts. The receiving page MUST also render the finding's description and MITRE technique tags, each technique tag linking to the rule's documentation page, so the analyst sees what fired and why independent of the graph state.

The receiving page's alert detail surface MUST show the alert's current status and expose its lifecycle controls (acknowledge, resolve, reopen), and the status MUST update on success. This is the single triage surface for the alert: the process detail panel MUST NOT restate the alert or duplicate its lifecycle controls, and instead references the process's alerts as links to their alert page.

When the alert is not attributed to a single process (a process-optional finding, where the attacker has no live process and the alert keys on an artifact such as a LaunchDaemon registration), the page MUST NOT render a silent blank canvas. It MUST instead present an explicit explanation that the detection is not tied to a running process, alongside an opt-in control that widens the view to the surrounding host activity. The page MUST NOT auto-expand to the full host tree. The explanation MUST survive a page reload of the alert link rather than depending on a non-persisted view toggle. Because triage lives on the alert detail surface rather than on a process node, a process-optional alert (which has no process node to select) MUST still be triageable from this page.

#### Scenario: Operator pivots from an alert to the host context

- **GIVEN** an alert is visible in the alert list
- **WHEN** the operator activates the alert's primary link
- **THEN** the UI navigates to the host's process tree pinned to the alert's time
- **AND** the receiving page renders an alert breadcrumb identifying severity, title, and time

#### Scenario: Operator pivots from a process-optional alert

- **GIVEN** an alert that is not attributed to a single process (its process id is zero)
- **WHEN** the operator pivots into the host's process tree from that alert
- **THEN** the page renders the finding's description and MITRE technique tags
- **AND** the page presents an explicit explanation that the detection is not attributed to a single process instead of a blank canvas
- **AND** the page offers an opt-in control to widen the view to the surrounding host activity rather than auto-expanding the full host tree

#### Scenario: Operator triages the alert from its detail surface

- **GIVEN** the operator has pivoted onto an alert's page
- **WHEN** the operator activates the acknowledge control on the alert detail surface
- **THEN** the alert's status transitions to acknowledged and the detail surface reflects the new status
- **AND** the process detail panel does not restate the alert or offer its own acknowledge / resolve controls

#### Scenario: A process-optional alert is triageable from the alert page

- **GIVEN** a process-optional alert (its process id is zero, so there is no process node to select) is open on its page
- **WHEN** the operator acknowledges it from the alert detail surface
- **THEN** the alert's status transitions to acknowledged even though no process node was selected

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

The UI SHALL provide a rule documentation page reachable by rule id from the coverage page and from the alert breadcrumb. The page MUST render the rule's title, summary, severity, ATT&CK technique mapping, event types, description, false-positive sources when present, and limitations when present. An unknown rule id MUST land on an empty state pointing back to the coverage page rather than producing a hard error.

#### Scenario: Rule detail renders documented fields

- **GIVEN** a registered rule with documentation
- **WHEN** the operator navigates to that rule's detail page
- **THEN** the UI renders the rule's title, summary, severity, ATT&CK techniques, event types, and description
- **AND** when the rule declares false positives or limitations, those sections render

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

### Requirement: Detection configuration admin views

The web UI SHALL provide an authenticated admin surface to view and edit detection configuration: per-rule mode (alert / disabled), an optional severity override, and false-positive exclusions. Monitor is NOT an operator-selectable mode; the detection engine still honors a legacy `monitor` value persisted on a rule setting, so the UI MUST display such a row (and let the operator migrate it to alert or disabled) but MUST NOT offer monitor as a new choice. The per-rule mode and severity controls MUST render uniformly for every registered rule (driven from the rule catalog), so a newly added rule appears without bespoke UI, and the table MUST show each rule's declared (default) severity alongside the optional override. The exclusion editor MUST let an operator create and delete global-scope exclusions with a typed match type, a value, a reason, and an optional expiration, and MUST surface the existing entries with their creation time and their author resolved to a display label: a human user's email, a service account's name, or "system" for the system principal, falling back to the raw principal identifier when the principal cannot be resolved. The match-type picker MUST offer only the match types the selected rule consults (sourced from the rule catalog's per-rule supported set), and MUST reset its selection when the rule changes, so an operator cannot submit an exclusion whose match type the rule would silently ignore. When an operator disables a rule, the UI MUST capture an operator-supplied reason before the change is submitted, because that reason is recorded in the audit trail; restoring a rule to alert and severity-only edits MAY use a system-generated reason. Mutations MUST go through the authenticated admin API and are subject to the same RBAC the API enforces. Per-rule schema-driven settings beyond mode + severity, exclusion editing, and host-group-scoped configuration are deferred to a later change (they land with the editable host groups and per-rule config-schema work).

#### Scenario: An operator adds an exclusion from the UI

- **GIVEN** an authenticated operator with detection-config write access
- **WHEN** they add an exclusion with a match type, value, and reason
- **THEN** the exclusion is created through the admin API
- **AND** it appears in the exclusion list with its creation time and its author shown as a resolved label (a user's email or a service account's name)

#### Scenario: Per-rule mode and severity controls render for every rule

- **GIVEN** the rule catalog registers a set of rules
- **WHEN** an operator opens the detection-configuration admin view
- **THEN** every registered rule shows mode and severity-override controls without UI changes specific to that rule
- **AND** each rule's declared default severity is shown alongside its optional override

#### Scenario: Disabling a rule requires an operator reason

- **GIVEN** an authenticated operator with detection-config write access
- **WHEN** they set a rule's mode to disabled
- **THEN** the UI captures an operator-supplied reason before submitting the change
- **AND** restoring the rule to alert or editing only its severity override does not require an operator-supplied reason (a system-generated reason is recorded instead)

#### Scenario: Monitor is not an operator-selectable mode

- **GIVEN** an authenticated operator viewing the rule-modes table
- **WHEN** they open a rule's mode control
- **THEN** a rule with no persisted monitor setting offers only alert and disabled
- **AND** a rule with a legacy persisted monitor value still displays monitor so the operator can migrate it to alert or disabled

#### Scenario: Exclusion author is shown as a resolved email

- **GIVEN** an exclusion whose author is a known user
- **WHEN** the operator views the exclusions list
- **THEN** the Created by column shows that user's email
- **AND** an exclusion whose author cannot be resolved falls back to the raw principal identifier

#### Scenario: Exclusion author shows a service account name

- **GIVEN** an exclusion whose author is a service account
- **WHEN** the operator views the exclusions list
- **THEN** the Created by column shows that service account's name rather than the raw principal identifier

#### Scenario: Exclusion match-type picker offers only the supported types for a rule

- **GIVEN** the rule catalog reports each rule's supported exclusion match types
- **WHEN** an operator selects a rule in the exclusion editor
- **THEN** the match-type picker offers only that rule's supported match types
- **AND** selecting a different rule resets the match-type selection to that rule's supported set

### Requirement: Admin settings exposes a user-management page

The web UI SHALL provide a user-management page in the Admin settings area that lists operators with their role and account status and lets an authorized admin change a user's role and enable or disable a user. The page and its controls SHALL be gated on the operator's permissions: the page requires `user.read`, and the role and status controls require `user.manage`. An operator lacking the grant SHALL NOT be shown the page or its mutation controls.

#### Scenario: The users page lists operators and changes a role

- **GIVEN** an admin viewing the user-management settings page
- **WHEN** the page loads and the admin selects a new role for a listed user
- **THEN** the list shows each user with their role and status
- **AND** the new role is submitted to the user-management API

### Requirement: Account menu conceals the signed-in identity until opened

The account menu in the top navigation SHALL NOT render the signed-in user's email in the always-visible bar. The collapsed trigger SHALL show only a non-identifying avatar (the email's first initial) and, for a break-glass session, the auth-method badge. The signed-in email SHALL be revealed only inside the account-menu dropdown, which opens on an explicit operator action. The trigger SHALL carry an accessible name so assistive technology can identify it even though it has no visible text label. This prevents passive disclosure of the operator's account to anyone viewing the screen, while keeping the identity one click away for a deliberate "who am I signed in as" check.

#### Scenario: The signed-in email is hidden until the account menu is opened

- **GIVEN** an operator is signed in and viewing any application page
- **WHEN** the account menu is collapsed (its default state)
- **THEN** the signed-in email is not present in the rendered page
- **AND** when the operator opens the account menu, the dropdown reveals the signed-in email

### Requirement: The settings area manages webhook destinations

The web UI SHALL provide a Webhooks section in the admin settings area that lists destinations and offers controls to add, edit, disable, delete, and test a destination, and that shows recent per-destination delivery outcomes. The section and its controls SHALL be gated on the operator's `webhook.manage` permission via the `useCan()` seam: an operator lacking the grant SHALL NOT see the section. The signing secret SHALL be entered write-only and SHALL NOT be displayed after it is saved.

#### Scenario: An admin adds a destination from the settings area

- **GIVEN** an admin viewing the settings area who holds `webhook.manage`
- **WHEN** they open the Webhooks section, add a destination with a URL and secret, and submit
- **THEN** the destination is sent to the configuration API and the refreshed list shows it without its secret

#### Scenario: An operator tests a destination from the UI

- **GIVEN** an admin viewing the Webhooks section
- **WHEN** they trigger a test delivery for a destination
- **THEN** the immediate outcome is shown in the UI

#### Scenario: The Webhooks section is hidden without the manage grant

- **GIVEN** an operator viewing the settings area who does not hold `webhook.manage`
- **WHEN** the settings area renders
- **THEN** the Webhooks section is not shown

#### Scenario: The secret field is write-only

- **GIVEN** an admin editing an existing destination
- **WHEN** the edit form renders
- **THEN** the signing-secret field is empty rather than prefilled from the server

### Requirement: The users page pre-provisions a new user and distinguishes the pending state

The web UI SHALL provide an "Add user" control on the user-management page that opens a form taking an email and a bindable role and submits it to the pre-provisioning API, then refreshes the list. The control SHALL be gated on the operator's `user.invite` permission via the `useCan()` seam: an operator lacking the grant SHALL NOT be shown the control. A pre-provisioned account (status `provisioned`) SHALL be rendered with a distinct pending indicator so it is visually distinguishable from active and disabled users immediately after creation.

#### Scenario: An admin pre-provisions a user from the users page

- **GIVEN** an admin viewing the user-management page who holds `user.invite`
- **WHEN** they open the add-user form, enter an email and select a role, and submit
- **THEN** the email and role are sent to the pre-provisioning API
- **AND** the refreshed list shows the new user with a pending indicator

#### Scenario: The add-user control is hidden without the invite grant

- **GIVEN** an operator viewing the user-management page who does not hold `user.invite`
- **WHEN** the page renders
- **THEN** the add-user control is not shown

### Requirement: The Hosts list surfaces per-host health

The web UI SHALL show each host's overall health status in the Hosts list as a badge distinct from the existing online/offline indicator, so that a host whose sensor is not activated is visually distinguishable from a healthy host at a glance. A host whose health is unknown SHALL render a neutral badge rather than a healthy one.

#### Scenario: An unhealthy host shows a needs-attention badge

- **GIVEN** a host whose overall health status is unhealthy
- **WHEN** the Hosts list renders
- **THEN** the host's row shows a needs-attention health badge distinct from its online/offline pill

#### Scenario: A host with unknown health shows a neutral badge

- **GIVEN** a host whose overall health status is unknown
- **WHEN** the Hosts list renders
- **THEN** the host's row shows a neutral health badge and not a healthy one

### Requirement: The host detail surfaces the health conditions

The web UI SHALL surface the host's agent-health rollup and per-component conditions inside the host header's Details popover rather than as a standalone panel. The Details trigger SHALL carry an attention marker (a coloured dot: amber when the rollup is degraded, red when it is unhealthy) only when the agent is not healthy, so a healthy or not-yet-reported host shows no health chrome in the always-visible header and a problem is visible at a glance without opening the popover. Opening the popover SHALL reveal the agent-health rollup as a single self-describing status pill (for example "Agent healthy" or "Agent needs attention") together with each component condition: the component, its status, a human-readable message, and how long it has been in its current state. When a required extension is not activated the message SHALL make the required action legible to an operator, for example that the security extension needs attention.

#### Scenario: The detail lists a component with its message and age

- **GIVEN** a host whose security extension is unhealthy with a not-activated message
- **WHEN** an operator opens the host header's Details popover
- **THEN** the popover shows the security extension with its unhealthy status, its message, and how long it has been in that state
- **AND** the Details trigger carried an attention dot before it was opened

#### Scenario: A fully healthy host shows a single healthy rollup

- **GIVEN** a host whose every component is healthy
- **WHEN** the operator views the host header
- **THEN** the Details trigger shows no attention dot
- **AND** opening the popover reveals a single "Agent healthy" status pill and the per-component conditions

### Requirement: Alert list is the home view

The UI SHALL render the alert list as the home view of the authenticated application: navigating to the application root SHALL route to the alert list. When the operator's permission set does not confer the read action that gates the alert list, the root SHALL instead route to the first navigation entry the permission set does confer, in the navigation's display order, so the operator lands on a usable surface rather than a no-access state. The landing fallback SHALL be derived from the same permission-gated navigation model used to render the navigation entries, not from a separate role-to-route mapping.

#### Scenario: Root routes to the alert list

- **GIVEN** an authenticated operator whose permission set contains `alert.read`
- **WHEN** the operator navigates to the application root
- **THEN** the UI renders the alert list

#### Scenario: Operator without alert read lands on their first permitted surface

- **GIVEN** an authenticated operator whose permission set does not contain `alert.read`
- **WHEN** the operator navigates to the application root
- **THEN** the UI routes to the first navigation entry in display order that the operator's permission set confers
- **AND** no no-access state is rendered for the landing itself

### Requirement: Alert-first navigation order

The top navigation SHALL present its entries in the order Alerts, Hosts, Application control, Coverage, subject to the existing capability gating that hides entries the operator cannot read. The Hosts entry SHALL be highlighted as active on both the host list route and a host's process tree route.

#### Scenario: Navigation lists Alerts first

- **GIVEN** an authenticated operator whose permission set confers every navigation entry
- **WHEN** the authenticated application renders its navigation
- **THEN** the entries appear in the order Alerts, Hosts, Application control, Coverage

#### Scenario: Hosts entry active on host detail

- **GIVEN** an authenticated operator viewing a host's process tree page
- **WHEN** the navigation renders
- **THEN** the Hosts entry is highlighted as the active entry

### Requirement: Host list page

The UI SHALL render an enrolled host list on a dedicated hosts page reachable from the Hosts navigation entry. The page SHALL open with a fleet-overview summary of how many hosts are online, how many are offline, and the total host count, computed from the same online/offline classification used by the rows. Each row MUST identify the host by its enrollment hostname over its full hardware identifier (falling back to the hardware identifier alone when no enrollment hostname is known), show the host's platform, show whether it is online or offline by comparing the host's last-seen timestamp to the current time, and show the host's running event count. A host MUST be classified online when its last-seen timestamp is within the last 5 minutes and offline otherwise. Activating a row MUST navigate to that host's process tree.

The per-host platform column maps the server's platform value to a display label and shows "unknown" for a host with no recorded platform.

#### Scenario: Host list renders rows for enrolled hosts

- **GIVEN** the server has at least one enrolled host
- **WHEN** the operator opens the hosts page
- **THEN** the UI renders a row per host with the host identity, an online/offline pill, the event count, and a relative last-seen label

#### Scenario: Host list shows hostname and a fleet summary

- **GIVEN** the server returns hosts with enrollment hostnames, plus one host with no enrollment hostname
- **WHEN** the operator opens the hosts page
- **THEN** the UI shows a summary of online, offline, and total host counts
- **AND** each host cell shows the enrollment hostname over the full hardware identifier, and a host with no enrollment hostname shows the hardware identifier alone

#### Scenario: Host rows show the host platform

- **GIVEN** the server returns a darwin host, a windows host, and a host with no platform
- **WHEN** the operator opens the hosts page
- **THEN** each row shows a platform label, mapping darwin to macOS and windows to Windows
- **AND** the host with no platform shows "unknown"

#### Scenario: Clicking a host opens its process tree

- **GIVEN** the host list is displayed
- **WHEN** the operator activates a host row
- **THEN** the UI navigates to the process tree page scoped to that host id

### Requirement: The alert list identifies a host by name

The alert list's Host column SHALL identify each alert's host by its enrollment hostname, falling back to the full hardware identifier only when no enrollment hostname is known, matching the host list and the search results so an analyst reads a recognizable name rather than a hardware UUID. The full hardware identifier SHALL remain available (for example in the control's tooltip), and the host control SHALL continue to open that host's process tree.

#### Scenario: Alert list shows the enrollment hostname

- **GIVEN** alerts whose hosts have enrollment hostnames, plus one alert on a host with no known hostname
- **WHEN** the alert list renders
- **THEN** each alert's Host cell shows the host's enrollment hostname
- **AND** the alert on the host with no known hostname shows that host's hardware identifier instead

### Requirement: The process detail omits a self-referential alert link

When the process detail panel is opened from an alert's page, its "Related alerts" references SHALL omit the alert whose page is currently open, so the panel never links back to the page the operator is already on. Every other alert on the process SHALL still be listed. When the panel is opened outside an alert context, every alert on the process SHALL be listed.

#### Scenario: Related alerts omit the alert whose page is open

- **GIVEN** a process has two alerts and the operator is on one of those alert's pages
- **WHEN** the process detail panel lists the process's Related alerts
- **THEN** the alert whose page is open is omitted from the list
- **AND** the process's other alert is still shown as a link to its alert page

### Requirement: The process tree hides the system-noise toggle when it changes nothing

The process tree's "Show system" toggle (which reveals system-path processes hidden by default) SHALL be offered only when flipping it would change the rendered tree. When the current view has no hidden system-path process to reveal (for example an alert chain whose only system-path nodes are the alerted process and its ancestors, which are shown regardless), the toggle SHALL NOT be rendered, so the operator is never presented with a control that does nothing.

#### Scenario: The toggle is hidden when there is no system noise to reveal

- **GIVEN** a process tree whose visible nodes include no system-path process that is hidden by default
- **WHEN** the tree renders
- **THEN** the "Show system" toggle is not shown

#### Scenario: The toggle is shown when system processes are hidden

- **GIVEN** a process tree that contains a system-path process hidden by default
- **WHEN** the tree renders
- **THEN** the "Show system" toggle is shown so the operator can reveal it

### Requirement: The kill action is disabled once the process has exited

The process detail panel's "Kill process" control SHALL be disabled when the process has already exited, because a kill targets a live PID and after exit that PID is either free or reused by an unrelated process, so a kill-by-pid could terminate the wrong process. The disabled control SHALL make the reason legible (that the process has already exited).

#### Scenario: An exited process cannot be killed from the detail panel

- **GIVEN** a process whose detail panel is open and which has an exit time
- **WHEN** the operator views the "Kill process" control
- **THEN** the control is disabled and indicates that the process has already exited
- **AND** activating it dispatches no kill command

### Requirement: Process node conviction evidence

Hovering a process node in the tree SHALL show the process's full command line and its derived code-signing verdict without opening the detail panel. Command lines SHALL be rendered faithfully: an argument containing whitespace or a quote is quoted so argv boundaries stay visible. The verdict SHALL be derived from the code-signing fields the node carries and SHALL distinguish: unsigned (no code-signing block reported, or a block with no identity), invalid (a reported signature the kernel no longer considers valid), ad-hoc (the ad-hoc signing flag set), Developer ID with the team identifier (a non-empty team id), Apple platform (the platform-binary flag), and signed (a signing identity with none of the above). A fork-only node (a process that has not exec'd) SHALL show its command line without a verdict: it runs its parent's inherited image, and labeling it unsigned would be a false conviction. Nodes whose verdict is unsigned, invalid, or ad-hoc SHALL carry a visible marker in the graph, distinct from the alert styling and preserved while the node is search-highlighted. For an aggregated node, the hover SHALL state the group size and show the representative process's command line and verdict.

#### Scenario: Hovering a node shows the command line and verdict

- **GIVEN** a rendered process tree containing a Developer ID-signed process
- **WHEN** the operator hovers its node
- **THEN** a tooltip shows the process's full command line
- **AND** the verdict names Developer ID with the team identifier
- **AND** the detail panel does not open

#### Scenario: Unsigned and ad-hoc nodes are marked in the graph

- **GIVEN** a tree containing an unsigned process and an ad-hoc-signed process
- **WHEN** the tree renders
- **THEN** both nodes carry the evidence marker
- **AND** a platform-signed process's node does not

#### Scenario: Aggregated node hover describes the group

- **GIVEN** a tree containing an aggregated node collapsing several identical-path siblings
- **WHEN** the operator hovers it
- **THEN** the tooltip states the member count and shows the representative's command line and verdict

### Requirement: Fleet-wide connection and DNS search

The search page SHALL offer connection and DNS search modes alongside process search, selectable from the page and reflected in the URL so each mode is bookmarkable. Connection mode SHALL query the fleet-wide connection search endpoint for a remote address; DNS mode SHALL query the fleet-wide DNS search endpoint for a domain. Like process mode, each event mode SHALL open on the fleet's most recent events of that type and narrow to an exact remote address or domain once one is supplied, rather than sitting behind a prompt until an artifact is entered. Event results SHALL render as a table showing, per event, the time, the host (its enrollment hostname when known, else the host identifier), the originating process, and the mode-specific detail: for a connection the direction, protocol, and remote address with port; for a DNS query the queried domain, the query type, and the resolved addresses. As with process search, the page SHALL show, when more results remain, a control that loads and appends the next page, and SHALL let the operator narrow either mode to a single host. The page SHALL show the total number of matches for a filtered search; for the unfiltered recent-events listing (which reports no total) it SHALL show only the number of rows currently loaded.

#### Scenario: Connection mode lists fleet-wide connections to an address

- **GIVEN** the connection search endpoint returns matching connections across more than one host
- **WHEN** the operator opens the search page in connection mode with a remote address in the URL
- **THEN** the page shows a row per connection with the host, the process, and the remote address and port
- **AND** the page shows the total number of matches

#### Scenario: DNS mode lists fleet-wide lookups of a domain

- **GIVEN** the DNS search endpoint returns matching queries across more than one host
- **WHEN** the operator opens the search page in DNS mode with a domain in the URL
- **THEN** the page shows a row per query with the host, the process, the queried domain, the query type, and the resolved addresses

#### Scenario: An event mode opens on recent events

- **GIVEN** the search page is opened in connection or DNS mode with no artifact value in the URL
- **WHEN** the page renders
- **THEN** it issues a search with no artifact filter and lists the fleet's most recent events of that type

#### Scenario: Load more appends the next page of events

- **GIVEN** an event result set larger than one page, so the response carries a next cursor
- **WHEN** the operator activates the load-more control
- **THEN** the next page's events are appended to the table using the cursor
- **AND** when no cursor remains the load-more control is not shown

### Requirement: Network artifact search pivots

The process detail panel's network section SHALL offer a "search fleet" pivot on each remote address and on each DNS query name. Activating the remote-address pivot SHALL open the search page in connection mode pre-filtered to that address; activating the DNS pivot SHALL open the search page in DNS mode pre-filtered to that query name.

#### Scenario: Pivoting from a remote address searches connections fleet-wide

- **GIVEN** the process detail panel shows a network connection to a remote address
- **WHEN** the operator activates that connection's search pivot
- **THEN** the UI opens the search page in connection mode filtered to that remote address across all hosts

#### Scenario: Pivoting from a DNS query searches lookups fleet-wide

- **GIVEN** the process detail panel shows a DNS query for a domain
- **WHEN** the operator activates that query's search pivot
- **THEN** the UI opens the search page in DNS mode filtered to that domain across all hosts

### Requirement: Fleet-wide search page

The UI SHALL provide a search page, reachable from a navigation entry gated on the process-read action, that queries the fleet-wide process search endpoint. The page SHALL derive its active filters from the URL query string so it is bookmarkable and so a pivot is a link, and SHALL render the results as a table showing, per process, the fork time, the host (its enrollment hostname when known, else the host identifier), the process name, the parent, the command line, the user, the code-signing verdict, and the exit reason. The page SHALL present the active filters as removable chips and SHALL let the operator add a filter for host, path, hash, uid, or signing verdict. Because results are keyset-paginated, the page SHALL show the total number of matches and, when more results remain, a control that loads the next page and appends it rather than replacing the current rows. Activating a result row SHALL open that host's process tree anchored at the matching process.

#### Scenario: Search renders matches with a total and host names

- **GIVEN** the process search endpoint returns matching processes across more than one host
- **WHEN** the operator opens the search page with a filter in the URL
- **THEN** the page shows a row per match with the host's name, the command line, and the signing verdict
- **AND** the page shows the total number of matches

#### Scenario: Removing a chip drops that filter

- **GIVEN** the search page displayed with a path filter and a signing filter active as chips
- **WHEN** the operator removes the path chip
- **THEN** the path filter is dropped from the URL and the results reflect the remaining filters

#### Scenario: Load more appends the next page

- **GIVEN** a result set larger than one page, so the response carries a next cursor
- **WHEN** the operator activates the load-more control
- **THEN** the next page's rows are appended to the table using the cursor
- **AND** when no cursor remains the load-more control is not shown

#### Scenario: A result row opens the host tree at the process

- **GIVEN** the search results are displayed
- **WHEN** the operator activates a row
- **THEN** the UI navigates to that host's process tree anchored at the matching process's time

### Requirement: Host page search pivots

The process detail panel SHALL offer a "search all hosts" pivot next to each artifact the fleet-wide search can filter on: the path, the SHA-256 hash, the user, and the code-signing verdict. Activating a pivot SHALL open the search page pre-filtered by that artifact. Artifacts the endpoint cannot filter (the signing identity and team identifier) SHALL remain copy-only without a pivot, so no pivot leads to an unfilterable search.

#### Scenario: Pivoting from a hash searches the fleet

- **GIVEN** the process detail panel is displayed for a process with a SHA-256 hash
- **WHEN** the operator activates the hash's search pivot
- **THEN** the UI opens the search page filtered to that hash across all hosts

#### Scenario: Unfilterable artifacts have no pivot

- **GIVEN** the detail panel shows a signing identity and team identifier
- **WHEN** the panel renders
- **THEN** those rows offer copy but no search pivot

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

### Requirement: Host event timeline view

The host page SHALL offer a timeline view alongside the process graph, selectable from the page with the active view reflected in the URL so a switch is bookmarkable and preserves the active time window and any alert anchor. The graph SHALL remain the default view. The timeline view SHALL render the host's exec, network-connection, and DNS-query events for the active time window as a flat table in descending event-time order, showing per event the time, the event type, the originating process, and the type-specific detail (for a connection the remote address and port; for a DNS query the query name and resolved addresses). The timeline SHALL be filterable by event type and by a text match, SHALL page additional results on demand rather than replacing the current rows, and SHALL show the total number of matching events. Switching between the graph and the timeline SHALL NOT change the active time window. When the page is entered for an alert with the alert-chain focus active, the timeline SHALL scope to the alert chain (only events from the alerted process and its ancestors and descendants), mirroring the graph's focus, and the shared "Alert chain / Full tree" control SHALL switch the scope for both views at once; when the focus is off, the timeline SHALL show the full host event stream.

#### Scenario: Timeline view lists window events filterable by type

- **GIVEN** a host with exec, network, and DNS events in the active window
- **WHEN** the operator switches to the timeline view
- **THEN** the events are listed newest-first with their type and originating process
- **AND** selecting an event-type filter narrows the list to that type

#### Scenario: Timeline scopes to the alert chain

- **GIVEN** the host page entered for an alert with the alert-chain focus active
- **WHEN** the operator switches to the timeline view
- **THEN** the timeline lists only events from the alert chain (the alerted process and its ancestors and descendants) and indicates it is scoped to the chain
- **AND** turning the shared focus off widens the timeline to the full host event stream

#### Scenario: The graph and timeline share one time window

- **GIVEN** the host page with a time window set on the graph view
- **WHEN** the operator switches to the timeline view
- **THEN** the timeline queries the same window
- **AND** switching back to the graph leaves the window unchanged

#### Scenario: A text filter narrows the timeline

- **GIVEN** the timeline view is displayed
- **WHEN** the operator enters a text filter
- **THEN** only events whose payload matches the text are listed

### Requirement: Graph and timeline cross-navigation

A timeline row SHALL link to its originating process in the graph: activating it switches to the graph view anchored at the event's time and selects the process that owned the event. A process node's detail panel SHALL offer a "show in timeline" action that switches to the timeline view and emphasizes that process's events. A timeline connection or DNS row SHALL offer the same fleet-wide "search" pivot on its remote address or query name that the process detail panel offers.

#### Scenario: A timeline row opens its process in the graph

- **GIVEN** the timeline view lists an event owned by a known process
- **WHEN** the operator activates the row's process link
- **THEN** the UI switches to the graph view anchored at the event time and selects that process

#### Scenario: A process node links to its timeline rows

- **GIVEN** the process detail panel is shown for a process in the graph view
- **WHEN** the operator activates "show in timeline"
- **THEN** the UI switches to the timeline view with that process's events emphasized

### Requirement: Inline MITRE technique tags

The UI SHALL surface an alert's MITRE ATT&CK technique identifiers inline where investigation happens, not only on the alert breadcrumb. An alerted process node's hover tooltip SHALL show the technique ids of that node's alerts. The process detail panel SHALL show, for each of the process's alerts, that alert's technique ids as badges that link to the rule's documentation page. A host-timeline row whose event triggered an alert SHALL show that alert's technique ids, also linked to the rule's documentation page. A node, panel entry, or row with no technique mapping SHALL show no technique tags.

#### Scenario: An alerted node tooltip shows its techniques

- **GIVEN** a process node has an alert that maps to one or more techniques
- **WHEN** the operator hovers the node
- **THEN** the tooltip shows those technique ids
- **AND** a node with no alert shows no technique tags

#### Scenario: The detail panel links alert techniques to the rule page

- **GIVEN** the detail panel is shown for a process with an alert that maps to a technique
- **WHEN** the panel renders the alert
- **THEN** the technique id is shown as a badge linking to that alert's rule documentation page

#### Scenario: A timeline row for a triggering event shows the technique

- **GIVEN** a host timeline row whose event id is among an alert's triggering events
- **WHEN** the timeline renders the row
- **THEN** the row shows that alert's technique ids linked to the rule documentation page
- **AND** a row whose event triggered no alert shows no technique tags

### Requirement: Host page time navigation

The host page SHALL present exactly one compact time control at rest, labeled with the active window ("Last 1 hour" for a relative window, a compact date-time span for an absolute one). Activating it SHALL open a popover offering relative quick-picks and an absolute from/to selection, either of which sets the window for every view on the page. The control SHALL include arrow affordances that shift the active window backward or forward by its own width, and a shifted window SHALL read as an absolute span. Arriving from an alert SHALL keep the existing anchored default (a wide window ending at the alert time).

The page SHALL render an activity histogram of process starts over the active window, and activating a histogram bucket SHALL narrow the active window to that bucket's span, reflected in the time control's label. The histogram SHALL come from the server-aggregated endpoint so it stays correct even when the rendered tree is truncated.

#### Scenario: One control at rest with relative and absolute selection

- **GIVEN** the host page is displayed
- **WHEN** the operator opens the time control and picks a relative quick-pick
- **THEN** the control's label names the relative window and the tree refetches for it
- **AND** picking an absolute from/to instead sets the window to that span and the label reads the span

#### Scenario: Shift arrows move the window by its width

- **GIVEN** an active one-hour window
- **WHEN** the operator activates the shift-back arrow
- **THEN** the active window becomes the previous hour as an absolute span
- **AND** the tree refetches for it

#### Scenario: Histogram bucket click narrows the window

- **GIVEN** the histogram shows a spike bucket
- **WHEN** the operator activates that bucket
- **THEN** the active window narrows to the bucket's span
- **AND** the time control's label reads the resulting absolute span

#### Scenario: Alert entry keeps its anchored window

- **GIVEN** the operator pivots from an alert
- **WHEN** the host page opens
- **THEN** the active window is the wide default ending at the alert's time, as before
