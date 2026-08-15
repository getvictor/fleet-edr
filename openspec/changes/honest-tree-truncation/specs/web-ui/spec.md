# web-ui delta

## MODIFIED Requirements

### Requirement: Process tree visualization

The UI SHALL render the process tree page for a host as a hierarchical visualization in which each node represents a process and edges represent parent-child fork/exec relationships. Activating a process node MUST open a side panel that displays the process's investigation detail. The page MUST support panning, zooming, and a search affordance that jumps the viewport to matching nodes. When the server collapses repeated identical-path siblings into an aggregated node, the UI MUST render that node as a group badge showing the member count (a "×N" affordance) rather than as a single process, and activating the aggregated node MUST expand it in place to reveal the sample of underlying members rather than opening the process detail panel; a member surfaced by that expansion behaves as an ordinary process node. Expanding an aggregated node in place is the affordance for inspecting its members; the page does not carry a separate global flatten control.

When the server reports the read as truncated, the UI MUST display a notice stating how many processes are shown out of how many matched the window, so the analyst is never shown a partial tree that looks complete. The notice MUST name the ways to see the rest, namely narrowing the time range or using search. The UI MUST take both counts from the server's result metadata rather than inferring them from the requested limit or from the number of rendered nodes. When the server does not report the read as truncated, the UI MUST NOT display the notice.

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

#### Scenario: A truncated tree tells the analyst what is missing

- **GIVEN** a host whose window matched more processes than the server returned
- **WHEN** the process tree renders
- **THEN** the UI shows a notice naming the number of processes shown and the number that matched
- **AND** the notice names narrowing the time range or using search as the ways to see the rest

#### Scenario: A complete tree shows no truncation notice

- **GIVEN** a host whose window matched no more processes than the server returned
- **WHEN** the process tree renders
- **THEN** the UI shows no truncation notice
