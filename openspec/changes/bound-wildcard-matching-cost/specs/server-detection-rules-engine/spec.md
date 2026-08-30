# Server detection rules engine: a wildcard pattern is compiled, not re-scanned delta

## ADDED Requirements

### Requirement: Wildcard matching cost does not depend on the event value being adversarial

The system SHALL compile a rule's wildcard pattern when the rule loads, and SHALL match it without re-scanning any part of the pattern against the value more than once per candidate position.

The cost of testing a field SHALL NOT be materially increased by the content of the event value. A value is attacker-supplied and a pattern is not, so a matcher whose cost depends on the value lets a host choose how much work the server does per rule, per field, for every event it sends.

Matching SHALL be unchanged by compilation. A pattern SHALL match exactly the values it matched before, because an optimisation that alters what a detection matches changes what fires, silently and without an error to notice.

#### Scenario: A literal run after a star is checked once, not at every offset

- **GIVEN** a pattern whose last element is a literal run following a star
- **WHEN** it is prepared for matching
- **THEN** that run is held as an anchor tested against the end of the value, rather than as something retried at each offset

#### Scenario: Compilation does not change what a pattern matches

- **GIVEN** any wildcard pattern and any value
- **WHEN** both the compiled matcher and the reference implementation are asked
- **THEN** they answer identically
