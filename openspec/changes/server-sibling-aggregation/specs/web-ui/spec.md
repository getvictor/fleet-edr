## MODIFIED Requirements

### Requirement: Process tree visualization

The UI SHALL render the process tree page for a host as a hierarchical visualization in which each node represents a process and edges represent parent-child fork/exec relationships. Activating a process node MUST open a side panel that displays the process's investigation detail. The page MUST support panning, zooming, and a search affordance that jumps the viewport to matching nodes. When the server collapses repeated identical-path siblings into an aggregated node, the UI MUST render that node as a group badge showing the member count (a "×N" affordance) rather than as a single process, and activating the aggregated node MUST expand it in place to reveal the sample of underlying members rather than opening the process detail panel; a member surfaced by that expansion behaves as an ordinary process node. The page MUST provide a persisted flatten control that, when enabled, refetches and renders the raw un-aggregated forest so an analyst can see every node.

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

#### Scenario: The flatten control shows every node

- **GIVEN** a process tree showing aggregated "×N" nodes
- **WHEN** the operator enables the flatten control
- **THEN** the UI refetches and renders the raw forest with every repeated sibling as its own node
