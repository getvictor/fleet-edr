# Web UI Specification (delta)

## ADDED Requirements

### Requirement: Add-rule modal carries an enforcement selector

The add-rule modal in the Application Control screen SHALL provide an enforcement selector with
the options `PROTECT` and `DETECT`. The selector SHALL default to `DETECT` so a new rule lands
in log-only mode unless the operator explicitly chooses to block. The selected value SHALL be
passed to the create-rule API call as the rule's `enforcement` field. The modal SHALL render a
short explanation next to the selector noting that DETECT rules log a would-block alert without
preventing the exec, and that the operator can promote the rule to PROTECT after observing the
alerts.

#### Scenario: A new rule defaults to Detect

- **GIVEN** an operator opens the add-rule modal
- **WHEN** the modal renders
- **THEN** the enforcement selector shows `DETECT` as the currently selected value

#### Scenario: An operator can submit a PROTECT rule with one click

- **GIVEN** an operator opens the add-rule modal and types a valid identifier and reason
- **WHEN** the operator changes the enforcement selector to `PROTECT` and clicks Save
- **THEN** the create-rule API call carries `enforcement='PROTECT'`

### Requirement: Policy detail surfaces enforcement and offers Promote-to-Protect

The policy detail view SHALL show the rule's `enforcement` value in the rules table. For rules
with `enforcement='DETECT'` the view SHALL render a per-row `Promote to Protect` action. Clicking
the action opens a confirmation modal that requires a non-empty `reason`. Submitting calls
`PATCH /api/v1/app-control/rules/{id}` with `{enforcement: "PROTECT", reason}`. On success the
row's enforcement value updates optimistically; on failure the modal surfaces the typed error.

#### Scenario: Detect rule shows the Promote action

- **GIVEN** a policy contains a rule with `enforcement='DETECT'`
- **WHEN** the operator opens the policy detail view
- **THEN** the rule's row shows a visible `Promote to Protect` action

#### Scenario: Protect rule does not show the Promote action

- **GIVEN** a policy contains a rule with `enforcement='PROTECT'`
- **WHEN** the operator opens the policy detail view
- **THEN** the rule's row does NOT show a `Promote to Protect` action

#### Scenario: Promote-to-Protect requires a reason

- **GIVEN** the Promote-to-Protect confirmation modal is open
- **WHEN** the operator attempts to submit without entering a reason
- **THEN** the modal refuses to submit and surfaces a visible error explaining the reason is
  required

#### Scenario: Promote-to-Protect updates the rule

- **GIVEN** the Promote-to-Protect confirmation modal is open for a Detect rule
- **WHEN** the operator enters a reason and submits
- **THEN** the API call PATCHes the rule with `{enforcement: "PROTECT", reason: <text>}`
- **AND** the rules table row optimistically renders the rule as PROTECT

### Requirement: Alerts list distinguishes block vs would-block subtypes

The alerts list SHALL render the `subtype` field of each alert as a distinct visual chip. Alerts
with `subtype='block'` SHALL render with a chip labelled "Blocked" in a visually-stronger style
than alerts with `subtype='would_block'`, which SHALL render with a chip labelled "Would have
blocked". Alerts with `subtype='detection'` continue to render as today (no subtype chip, or a
neutral chip; UI choice). Unknown subtype values SHALL render with a fallback chip labelled
"Application Control" so future Phase B subtypes don't render blank.

#### Scenario: Block alerts render with a Blocked chip

- **GIVEN** an alert exists with `source='application_control'` and `subtype='block'`
- **WHEN** the alerts list renders the alert
- **THEN** the row shows a chip labelled "Blocked"

#### Scenario: Would-block alerts render with a Would-have-blocked chip

- **GIVEN** an alert exists with `source='application_control'` and `subtype='would_block'`
- **WHEN** the alerts list renders the alert
- **THEN** the row shows a chip labelled "Would have blocked"

#### Scenario: Unknown subtype renders a fallback chip

- **GIVEN** an alert exists with `source='application_control'` and an unrecognised subtype
- **WHEN** the alerts list renders the alert
- **THEN** the row shows a chip labelled "Application Control"
- **AND** the row does not render blank or break the table layout

### Requirement: Alerts list filters by subtype

The alerts list SHALL accept a `subtype` filter alongside the existing `source` filter so an
operator iterating on a Detect-mode rule can isolate the "would have blocked" alerts. The filter
control SHALL be visible whenever `source='application_control'` is selected and SHALL offer
"All", "Blocked", and "Would have blocked" as preset values. Unknown subtype values are not
surfaced as preset options; future Phase B subtypes get UI presets when their respective changes
land.

#### Scenario: Filter to would-block only

- **GIVEN** the alerts list is filtered to `source=application_control`
- **WHEN** the operator selects "Would have blocked" in the subtype filter
- **THEN** the list shows only alerts with `subtype='would_block'`
- **AND** the URL query string carries `subtype=would_block`

#### Scenario: Subtype filter hidden when source is not application_control

- **GIVEN** the alerts list is filtered to `source=detection`
- **WHEN** the operator looks for a subtype filter
- **THEN** no subtype filter control is visible
