# Web UI: related-process context for process-optional alerts delta

## ADDED Requirements

### Requirement: Related-process context for process-optional alerts

When a process-optional alert's detail carries a non-empty set of related processes (the artifact's writer, the persisted executable's runs), the process tree page SHALL render those processes as the scoped focus of the graph, labelled by their role, instead of the "not attributed to a single process" explanation. The page SHALL NOT expand to the full host tree to surface them; it scopes to the related set, preserving the opt-in to widen. When the related set is empty, the page SHALL fall back to the explicit explanation and opt-in defined by the process-optional alert pivot.

#### Scenario: Related processes are shown when available

- **GIVEN** a process-optional alert whose detail includes related processes (for example the process that wrote the LaunchDaemon plist)
- **WHEN** the operator pivots into the host's process tree from that alert
- **THEN** the graph is scoped to the related processes, labelled by their role
- **AND** the full host tree is not auto-expanded

#### Scenario: Falls back to the explanation when no related processes exist

- **GIVEN** a process-optional alert whose detail includes no related processes
- **WHEN** the operator pivots into the host's process tree from that alert
- **THEN** the page renders the explicit "not attributed to a single process" explanation with the opt-in to widen to the surrounding host activity
