# Server detection rules engine: a wildcard pattern is compiled, not re-scanned delta

## ADDED Requirements

### Requirement: Wildcard matching cost does not depend on the event value being adversarial

The system SHALL compile a rule's wildcard pattern when the rule loads, and SHALL match it without re-scanning any part of the pattern against the value more than once per candidate position.

For a pattern fixed at load, the system SHALL check each of the pattern's star-separated segments against the value independently, and SHALL NOT retry an earlier segment because a later one failed. A value is attacker-supplied and a pattern is not, so a matcher that re-runs the whole pattern from a new offset lets a host choose how much work the server does per rule, per field, for every event it sends.

A literal run at either end of a pattern SHALL be checked once, against that end of the value, rather than at every offset.

This is a bound on re-scanning, not on the constant, and the difference is worth stating plainly. Verifying a candidate position still compares up to a segment's length, so a value dense in near-misses of one segment still costs more than a benign value of the same size. What it cannot do is compound: no failure sends the matcher back to re-run earlier segments, which is what made the previous implementation quadratic in the pattern as a whole.

Matching SHALL be unchanged by compilation. A pattern SHALL match exactly the values it matched before, because an optimisation that alters what a detection matches changes what fires, silently and without an error to notice.

#### Scenario: A literal run after a star is checked once, not at every offset

- **GIVEN** a pattern whose last element is a literal run following a star
- **WHEN** it is prepared for matching
- **THEN** that run is held as an anchor tested against the end of the value, rather than as something retried at each offset

#### Scenario: Compilation does not change what a pattern matches

- **GIVEN** any wildcard pattern and any value
- **WHEN** both the compiled matcher and the reference implementation are asked
- **THEN** they answer identically
