## ADDED Requirements

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
