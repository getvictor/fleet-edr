# web-ui

## MODIFIED Requirements

### Requirement: Host event timeline view

The host page SHALL offer a timeline view alongside the process graph, selectable from the page with the active view reflected in the URL so a switch is bookmarkable and preserves the active time window and any alert anchor. The graph SHALL remain the default view. The timeline view SHALL render the host's exec, network-connection, and DNS-query events for the active time window as a flat table in descending event-time order, showing per event the time, the event type, the originating process, and the type-specific detail (for a connection the remote address and port; for a DNS query the query name and resolved addresses). The timeline SHALL be filterable by event type and by a text match, SHALL page additional results on demand rather than replacing the current rows, and SHALL show the total number of matching events. Switching between the graph and the timeline SHALL NOT change the active time window. When the page is entered for an alert with the alert-chain focus active, the timeline SHALL scope to the alert chain (only events from the alerted process and its ancestors and descendants), mirroring the graph's focus, and the shared "Alert chain / Full tree" control SHALL switch the scope for both views at once; when the focus is off, the timeline SHALL show the full host event stream. The scope is keyed on each process's generation, which not every process carries, so the timeline SHALL distinguish three outcomes rather than two. When the chain cannot be scoped at all, either because no process in it carries a generation or because the alerted process is absent from the loaded process tree, the timeline SHALL show the full host event stream and SHALL state that it is doing so. It SHALL name a cause only where that cause is established: the absence of generations is provable from the resolved chain, while an unresolved chain has several possible causes, including a response truncated by the tree's row limit, so the timeline SHALL report only that the process is absent from the tree that was loaded and SHALL NOT attribute it to the time window. While the read is in flight or after it has failed, the timeline SHALL say nothing, because there is no loaded tree for anything to be absent from. When only some of them do, the timeline SHALL scope to the processes it can reach and SHALL state how many it omitted, because a list that presents itself as the alert chain while silently dropping part of that chain is worse than one that shows too much. When all of them do, the timeline SHALL scope without qualification.

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

#### Scenario: Timeline says so when it cannot scope to the chain

- **GIVEN** the host page entered for an alert whose chain processes carry no process generation
- **WHEN** the operator switches to the timeline view
- **THEN** the timeline lists the full host event stream
- **AND** it states that it is showing the whole host because the chain cannot be narrowed
- **AND** it does not simultaneously claim to be scoped to the alert chain

#### Scenario: Timeline distinguishes an absent chain from a chain without generations

- **GIVEN** the host page entered for an alert whose alerted process is absent from the loaded process tree, including when that tree was truncated by its row limit
- **WHEN** the operator switches to the timeline view
- **THEN** the timeline lists the full host event stream
- **AND** it states that the process is absent from the loaded tree
- **AND** it does not attribute the fallback to the time window or to missing generation data

#### Scenario: Timeline admits an alert chain it could only partly scope

- **GIVEN** the host page entered for an alert whose chain carries a process generation on some of its processes but not all
- **WHEN** the operator switches to the timeline view
- **THEN** the timeline scopes to the processes it can reach
- **AND** it states how many processes it omitted
- **AND** it does not present itself as scoped to the whole alert chain

#### Scenario: The graph and timeline share one time window

- **GIVEN** the host page with a time window set on the graph view
- **WHEN** the operator switches to the timeline view
- **THEN** the timeline queries the same window
- **AND** switching back to the graph leaves the window unchanged

#### Scenario: A text filter narrows the timeline

- **GIVEN** the timeline view is displayed
- **WHEN** the operator enters a text filter
- **THEN** only events whose payload matches the text are listed
