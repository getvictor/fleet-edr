# Web UI delta

## ADDED Requirements

### Requirement: Rule forms require an enforcement choice

The application-control Add rule and Paste many dialogs SHALL ask for the rule's enforcement, Detect or Protect, and SHALL describe what each does: Detect blocks nothing and records the matches that run, noting that a Protect rule that also matches still blocks, and Protect blocks. Neither SHALL be preselected, and saving SHALL stay disabled until one is chosen, because the server requires it and either choice made by default is wrong for someone. Reopening a dialog SHALL clear the choice. A saved rule SHALL carry the enforcement chosen, applied to every row of a paste.

#### Scenario: Neither enforcement is preselected

- **GIVEN** an operator opening the Add rule dialog with a valid identifier and a reason entered
- **WHEN** no enforcement has been chosen
- **THEN** neither Detect nor Protect is selected and saving is disabled
- **AND** choosing one enables saving and the saved rule carries it
- **AND** reopening the dialog clears the choice

#### Scenario: A paste applies the chosen enforcement to every row

- **GIVEN** an operator previewing a paste of several identifiers with a reason entered
- **WHEN** they choose Detect and save
- **THEN** every rule in the bulk upsert carries `enforcement=DETECT`

### Requirement: The policy rules table shows each rule's enforcement

The application-control policy page SHALL show each rule's enforcement in its rules table, as Detect or Protect, so an operator reading the list can tell which rules block and which only record.

#### Scenario: A rule's enforcement is visible in the list

- **GIVEN** a policy with a Detect rule and a Protect rule
- **WHEN** an operator opens the policy page
- **THEN** each rule's row shows its enforcement

### Requirement: A Detect rule can be promoted with its impact in view

The policy page SHALL let an operator promote a Detect rule to Protect, and move a Protect rule back to Detect, from the rule's row. Either change SHALL ask for a reason before it is saved. For an operator who may read detection tuning, where the match counts are served, each Detect rule's row and its promote dialog SHALL state what the rule would have blocked in the counted window, as runs and hosts, or as nothing recorded rather than as zero, and SHALL link to the rule's monitor records. For an operator who may not, the figure SHALL be left out rather than shown as zero. The monitor-records page for an application-control rule SHALL explain its records as executables that ran while the rule was in Detect mode, which it would have blocked.

#### Scenario: Promoting shows what the rule would have blocked

- **GIVEN** a Detect rule with counted would-block matches, and an operator who may read detection tuning
- **WHEN** the operator opens the policy page and promotes the rule
- **THEN** the row and the dialog state how many runs on how many hosts the rule would have blocked, linking to its records
- **AND** saving with a reason changes the rule's enforcement to Protect

#### Scenario: Without access to match counts the figure is left out

- **GIVEN** an operator who may not read detection tuning
- **WHEN** they open a policy page with a Detect rule
- **THEN** the rule can still be promoted and no would-block figure is shown

#### Scenario: App-control records read as would-block runs

- **GIVEN** the monitor-records page for an application-control rule
- **WHEN** it loads
- **THEN** it explains the records as executables the rule would have blocked in Detect mode
