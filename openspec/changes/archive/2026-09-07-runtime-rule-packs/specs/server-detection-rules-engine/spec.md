# Server detection rules engine

## ADDED Requirements

### Requirement: Replacing the active rule set is atomic

The system SHALL treat the active rule set as one immutable value and replace it atomically, so that a batch being evaluated while the set is replaced is evaluated against exactly one set. Evaluation SHALL take its view of the rules once and use that view throughout, so the indices it dispatches on and the rules it invokes can never come from different sets.

This is a precondition for loading rule packs at runtime rather than a preference. The processor evaluates batches from concurrent workers, and the dispatch indices are derived state rebuilt whenever the rules change, so replacing the rules while a batch is in flight would otherwise let one evaluation read indices built for a set it is no longer holding. The consequence is not a crash but a WRONG evaluation: a rule invoked for a batch that does not carry its event types, or worse, a rule skipped for one that does.

Replacement SHALL have replace semantics, not append, so a set loaded repeatedly does not accumulate duplicates of the same rule and evaluate it more than once per batch.

The derived indices SHALL remain reproducible from the rules alone, so they stay a per-replica cache in the sense ADR-0010 permits: they hold nothing a peer replica would need to serve the next request, and are rebuilt on load rather than shared.

#### Scenario: A batch evaluated during a replacement sees one consistent rule set

- **GIVEN** batches being evaluated concurrently while the active rule set is replaced repeatedly
- **WHEN** a replacement lands between an evaluation's dispatch decision and its invocation of the selected rules
- **THEN** that evaluation invokes rules from a single set, and every rule it invokes is one that set declared for the batch's event types
- **AND** no evaluation observes a partially replaced set

#### Scenario: Loading the active set repeatedly does not duplicate rules

- **GIVEN** an engine whose active rule set has already been loaded
- **WHEN** it is loaded again with the same rules
- **THEN** each rule appears once and is evaluated once per batch
