## MODIFIED Requirements

### Requirement: Alert-first navigation order

The top navigation SHALL present its entries in the order Alerts, Hosts, Search, Application control, Rules, subject to the existing capability gating that hides entries the operator cannot read. The Hosts entry SHALL be highlighted as active on both the host list route and a host's process tree route.

An entry whose section holds more than one surface SHALL be highlighted as active on any of them, so an operator moving between a section's surfaces is not told they have left it.

#### Scenario: Navigation lists Alerts first

- **GIVEN** an authenticated operator whose permission set confers every navigation entry
- **WHEN** the authenticated application renders its navigation
- **THEN** the entries appear in the order Alerts, Hosts, Search, Application control, Rules

#### Scenario: Hosts entry active on host detail

- **GIVEN** an authenticated operator viewing a host's process tree page
- **WHEN** the navigation renders
- **THEN** the Hosts entry is highlighted as the active entry

#### Scenario: The Rules entry stays active on coverage

- **GIVEN** an authenticated operator viewing the coverage surface
- **WHEN** the navigation renders
- **THEN** the Rules entry is highlighted as the active entry

## ADDED Requirements

### Requirement: Coverage is read beside the rules it is computed from

The rule catalogue and the coverage view SHALL be presented as two surfaces of one section, each reachable from the other without returning to the top navigation. The coverage layer is computed entirely from the registered rules and names them on every technique row, so an operator reading either is reading about the same corpus; presenting them as separate destinations asks them to know that already.

Both surfaces SHALL be reached on the same authorization, because a section whose surfaces answer to different actions would show an operator a way to a page that then refuses them.

The coverage surface SHALL keep its own path rather than becoming a path below the catalogue's. A fixed segment below the catalogue would rank above the identifier a rule's detail is read at, so a rule whose identifier matched that segment could not be reached at all, and every link already written to the coverage path would have to be rewritten to keep working.

#### Scenario: Each surface offers the other

- **GIVEN** an operator on either the rule catalogue or the coverage view
- **WHEN** the surface renders
- **THEN** it offers both surfaces of the section
- **AND** marks the one being read

#### Scenario: A rule identifier is not shadowed by the coverage surface

- **GIVEN** a rule whose identifier is the word the coverage surface is named by
- **WHEN** an operator opens that rule's detail
- **THEN** the rule's detail is shown rather than the coverage view
