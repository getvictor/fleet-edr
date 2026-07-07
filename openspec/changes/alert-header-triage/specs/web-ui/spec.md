## MODIFIED Requirements

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
