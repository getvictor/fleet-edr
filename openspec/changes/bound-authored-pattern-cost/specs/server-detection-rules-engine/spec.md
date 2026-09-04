# Server detection rules engine: an authored pattern's cost is bounded delta

## ADDED Requirements

### Requirement: A rule's pattern cannot make matching arbitrarily expensive

The system SHALL refuse a rule whose patterns would cost more than a bounded amount to match against one event, and SHALL refuse it when the rule loads rather than when it first evaluates.

This requirement exists because a premise expired. The bound on wildcard matching was stated for attacker-supplied VALUES against a trusted pattern; once operators author rules, the pattern is untrusted input too, and the cost a pattern imposes is paid once per value, per field, per rule, for every event.

The bounds SHALL be placed where every pattern passes through on its way to being matched, so that the validation a publish runs and the loading a server does cannot disagree about what is acceptable. A rule accepted at publish and refused at load, or the reverse, is worse than either answer alone.

Cost SHALL be bounded both per pattern AND per field, summed across that field's values. Per-pattern bounds alone do not bound what an event pays: a field's values are tried until one matches, so an event matching none of them pays for every one, and a field of individually cheap patterns can cost far more than any single pattern the bound would refuse.

The estimate SHALL reflect what matching actually costs rather than what a pattern looks like. Two corrections are recorded because each was wrong first. A wildcard pattern's cost is the LENGTH of a segment with a star on either side, not the count of single-character wildcards in it: such a segment is searched for at every candidate offset, and a run of literal characters there costs the same order as a run of wildcards. A regular expression's cost is the size of the program it compiles to, not the length of its source: counted repetition expands at compile time, so a seven-character source can produce an enormous program.

Where a cost can be removed rather than refused, the system SHALL remove it. Adjacent wildcards that mean what one wildcard means SHALL be collapsed when the pattern is compiled, because refusing a pattern that means nothing unusual serves nobody.

A refusal SHALL name the field and the limit it exceeded, and SHALL say whether the limit was reached by one pattern or by the field's values together. An operator who has just written a rule needs to know which part to change.

Bounds SHALL be set from measurement against the matcher, and a bound that constrains nothing SHALL NOT be added. A limit nobody can trip is not free: it trains a reader to treat the limits as decorative, and invites a later change to raise it without measuring.

Every rule the system ships SHALL still load, and a rule refused for cost SHALL NOT prevent the rest of the content from loading.

#### Scenario: A pattern costing more than the limit is refused

- **GIVEN** a rule with a pattern whose unanchored portion is longer than the limit allows, whether it is written as wildcards or as literal characters
- **WHEN** the rule is loaded
- **THEN** it is refused, naming the field and the limit

#### Scenario: A pattern anchored to the ends of the value costs nothing

- **GIVEN** a rule whose long pattern portion sits at the start or the end of the pattern rather than between two wildcards
- **WHEN** the rule is loaded
- **THEN** it is accepted, because such a portion is compared once rather than searched for at every offset

#### Scenario: A field costing more than the limit across its values is refused

- **GIVEN** a rule whose single field lists values that are each within the per-pattern limit but together exceed the field limit
- **WHEN** the rule is loaded
- **THEN** it is refused, naming the field and saying the limit was reached across its values
- **AND** a field listing many values that each cost nothing to match is still accepted

#### Scenario: Adjacent wildcards are collapsed rather than refused

- **GIVEN** a pattern containing a run of adjacent wildcards
- **WHEN** it is compiled
- **THEN** it costs what the same pattern with one wildcard costs
- **AND** it matches exactly what that pattern matches

#### Scenario: A rule refused for cost does not stop the others loading

- **GIVEN** content in which one rule exceeds a cost limit and the others do not
- **WHEN** the content is loaded
- **THEN** the offending rule is refused by name, with a reason
- **AND** every other rule in that content loads

#### Scenario: The content the system ships is unaffected

- **GIVEN** the rule content compiled into the build
- **WHEN** it is loaded
- **THEN** every rule that loaded before these bounds existed still loads
