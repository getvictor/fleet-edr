# Server detection rules engine: an authored pattern's cost is bounded delta

## ADDED Requirements

### Requirement: A rule's pattern cannot make matching arbitrarily expensive

The system SHALL refuse a rule whose pattern would cost more than a bounded amount to match against one value, and SHALL refuse it when the rule loads rather than when it first evaluates.

This requirement exists because a premise expired. The bound on wildcard matching was stated for attacker-supplied VALUES against a trusted pattern; once operators author rules, the pattern is untrusted input too, and the cost a pattern can impose is paid once per value, per field, per rule, for every event.

The bounds SHALL be placed where every pattern passes through on its way to being matched, so that the validation a publish runs and the loading a server does cannot disagree about what is acceptable. A rule accepted at publish and refused at load, or the reverse, is worse than either answer alone.

A refusal SHALL name the field and the limit it exceeded. An operator who has just written a rule needs to know which part to change, and a refusal that says only that the rule is too expensive sends them to guess.

Bounds SHALL be set from measurement against the matcher, and a bound that constrains nothing SHALL NOT be added. A limit nobody can trip is not free: it trains a reader to assume the limits are decorative, and it invites a later change to raise it without measuring.

Every rule the system ships SHALL still load. A bound that refuses vendored content is set wrong, and this is the check that keeps a bound honest as the corpus grows.

#### Scenario: A pattern with an unbounded run of single-character wildcards is refused

- **GIVEN** a rule whose pattern has more single-character wildcards in one unanchored run than the limit allows
- **WHEN** the rule is loaded
- **THEN** it is refused, naming the field and the limit
- **AND** the other rules in the same content still load

#### Scenario: A regular expression longer than the limit is refused

- **GIVEN** a rule whose regular-expression pattern is longer than the limit allows
- **WHEN** the rule is loaded
- **THEN** it is refused, naming the field and the limit

#### Scenario: A field testing more values than the limit is refused

- **GIVEN** a rule whose single field lists more values than the limit allows
- **WHEN** the rule is loaded
- **THEN** it is refused, naming the field and the limit

#### Scenario: The content the system ships is unaffected

- **GIVEN** the rule content compiled into the build
- **WHEN** it is loaded
- **THEN** every rule that loaded before these bounds existed still loads
