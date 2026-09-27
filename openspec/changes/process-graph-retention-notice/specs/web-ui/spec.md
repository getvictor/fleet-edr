## ADDED Requirements

### Requirement: The process graph says when its window predates retention

The process graph SHALL tell the operator when the window it shows starts before the moment the server reports process records are retained from: that processes from earlier in the window are missing unless an alert references them, and that the event timeline is kept separately. It SHALL say nothing when the window is inside retention or the server reports no boundary.

#### Scenario: An old window is labelled as aged out

- **GIVEN** a process graph whose window starts before the server's retention boundary
- **WHEN** the graph loads
- **THEN** a notice says process records from before the boundary have been deleted
- **AND** no notice appears for a window inside retention or when no boundary is reported
