# Detection rules engine

## ADDED Requirements

### Requirement: One exec-chain walk for both shell-chain rules

The rules that look for a shell on a process's own exec chain SHALL share one walk. Two copies of the same graph traversal drift, and a divergence between them decides whether a payload is detected at all depending on which rule sees it first.

The walk SHALL prefer the newest suitable generation on the chain. Where a shell replaced itself more than once, the generation closest to the payload is the one that ran it; the oldest is the most likely to fall outside the window, so preferring it loses chains whose newer shell was well within it.

The walk SHALL NOT report a shell whose claimed parent is absent from the graph, and SHALL defer instead. Exclusions match on the parent's path, so a finding naming an unresolved parent cannot be suppressed by an exclusion an operator has configured for it; an unsuppressable alert is a worse outcome than a deferral, which resolves when the parent's record arrives. A shell parented at the init process is a genuine no-parent case, not incomplete ancestry, and still counts.

#### Scenario: The newest suitable generation on the chain is preferred

- **GIVEN** a chain where a shell replaced itself twice before running a payload, the older generation outside the window and the newer inside it
- **WHEN** the batch is evaluated
- **THEN** the chain is reported, and the finding names the newer generation

#### Scenario: A shell whose parent is absent from the graph defers

- **GIVEN** a chain whose shell generation claims a parent that has no record in the graph, and whose parent is not the init process
- **WHEN** the batch is evaluated
- **THEN** no finding is produced, rather than one naming an unresolved parent
