# Detection rules engine

## ADDED Requirements

### Requirement: One exec-chain walk for both shell-chain rules

The rules that look for a shell on a process's own exec chain SHALL share one walk. Two copies of the same graph traversal drift, and a divergence between them decides whether a payload is detected at all depending on which rule sees it first.

The walk SHALL prefer the newest suitable generation on the chain. Where a shell replaced itself more than once, the generation closest to the payload is the one that ran it; the oldest is the most likely to fall outside the window, so preferring it loses chains whose newer shell was well within it.

The walk SHALL NOT report a shell whose claimed parent is absent from the graph. Exclusions match on the parent's path, so a finding naming an unresolved parent cannot be suppressed by an exclusion an operator has configured for it, and an alert that recurs with no way to silence it drives an operator to disable the rule entirely, losing every detection it makes rather than this one. A shell parented at the init process is a genuine no-parent case, not incomplete ancestry, and still counts.

The chain is DROPPED, not retried. This is the skip semantics the "Retryable evaluation on unmaterialized subject process" requirement already specifies for ancestor and parent-chain lookups: the retryable class covers the pid an event is about, not its ancestry. A parent record arriving later does not recover the detection, and the requirement here does not promise that it will.

#### Scenario: The newest suitable generation on the chain is preferred

- **GIVEN** a chain where a shell replaced itself twice before running a payload, the older generation outside the window and the newer inside it
- **WHEN** the batch is evaluated
- **THEN** the chain is reported, and the finding names the newer generation

#### Scenario: A shell whose parent is absent from the graph is not reported

- **GIVEN** a chain whose shell generation claims a parent that has no record in the graph, and whose parent is not the init process
- **WHEN** the batch is evaluated
- **THEN** no finding is produced, rather than one naming an unresolved parent, and the batch is acknowledged rather than retried
