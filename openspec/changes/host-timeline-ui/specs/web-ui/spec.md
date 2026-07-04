## ADDED Requirements

### Requirement: Host event timeline view

The host page SHALL offer a timeline view alongside the process graph, selectable from the page with the active view reflected in the URL so a switch is bookmarkable and preserves the active time window and any alert anchor. The graph SHALL remain the default view. The timeline view SHALL render the host's exec, network-connection, and DNS-query events for the active time window as a flat table in descending event-time order, showing per event the time, the event type, the originating process, and the type-specific detail (for a connection the remote address and port; for a DNS query the query name and resolved addresses). The timeline SHALL be filterable by event type and by a text match, SHALL page additional results on demand rather than replacing the current rows, and SHALL show the total number of matching events. Switching between the graph and the timeline SHALL NOT change the active time window.

#### Scenario: Timeline view lists window events filterable by type

- **GIVEN** a host with exec, network, and DNS events in the active window
- **WHEN** the operator switches to the timeline view
- **THEN** the events are listed newest-first with their type and originating process
- **AND** selecting an event-type filter narrows the list to that type

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
