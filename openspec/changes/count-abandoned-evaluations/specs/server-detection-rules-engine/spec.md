## ADDED Requirements

### Requirement: Evaluations a rule abandons are counted

When a rule needs the process record an event names and that record is still absent once the materialization grace has passed, the rule evaluates the event as if nothing matched. That decision is correct, since a record that has not arrived by then may never arrive, but it is also a detection that did not happen. The engine SHALL count each such abandon against the rule that made it, in the rule's durable evaluation counters, beside the count of retryable misses.

The two counts SHALL remain distinct. A miss inside the grace is a retry: the batch is re-evaluated and the event may yet be decided, so it SHALL NOT be counted as abandoned. Only a miss past the grace is. A rule whose record did materialize SHALL NOT record an abandon however old its event.

An abandon SHALL be counted once per rule and process within a batch, matching how those rules deduplicate their findings, so that the count is not inflated against at most one lost finding per process. The same process under a second rule SHALL count as that rule's own abandon.

Like the other evaluation counters, abandons SHALL be recorded per attempt, so a replayed batch counts its abandons again, and a reader SHALL interpret them as a rate against evaluations. Abandons SHALL NOT be bounded by the evaluation count: a miss is at most one per attempt, but one attempt over a batch can give up on several processes.

A rule that does not record its abandons SHALL have its abandon count reported as not measured rather than as zero, since its zero would be the same whether or not it gave up on anything. Days recorded before the count existed were not measured either, and SHALL NOT be reported as having no abandons. A read over a window in which any evaluation was made without counting abandons, including the day the count began and evaluations an older server made during a rolling upgrade, SHALL report the abandon count as not measured rather than as a total over the measured part alone.

A rule whose decision depends on the process only after an earlier graph read, such that a missing record ends its evaluation before the materialization decision is reached, is outside this requirement; the count covers only the point at which a rule chooses between waiting and giving up.

#### Scenario: A rule that gives up on a missing process record is counted

- **GIVEN** an event whose process record is still absent after the materialization grace has passed
- **WHEN** a rule that needs that record evaluates the event
- **THEN** the rule raises no finding and does not raise the retryable sentinel
- **AND** one abandon is recorded against that rule

#### Scenario: A miss inside the grace is a retry, not an abandon

- **GIVEN** an event whose process record is absent and which is still inside the materialization grace
- **WHEN** a rule that needs that record evaluates the event
- **THEN** the rule raises the retryable sentinel
- **AND** no abandon is recorded against that rule

#### Scenario: The count reaches the rule's durable evaluation counters

- **GIVEN** a batch in which one rule abandons several distinct processes and another rule abandons none
- **WHEN** the batch is evaluated and its statistics are written and read back
- **THEN** the first rule's evaluation counters carry its abandons, accumulated across writes
- **AND** the second rule's counters carry none
- **AND** the retryable-miss count is unaffected by the abandons

#### Scenario: Abandons are not bounded by evaluations

- **GIVEN** a rule's evaluation statistics in which the abandon count exceeds the evaluation count
- **WHEN** a client reads those statistics
- **THEN** the row is accepted as well formed

#### Scenario: Days before the count existed are not reported as zero

- **GIVEN** a rule whose evaluation counters include a day recorded before the abandon count existed
- **WHEN** its statistics are read over a window that includes that day
- **THEN** the abandon count is reported as not measured, while its other counters are reported as usual
- **AND** a read over a window that excludes that day reports the abandon count

#### Scenario: An uncounting rule is not reported as having none

- **GIVEN** a rule that does not record the abandons it makes
- **WHEN** its statistics are written and read back
- **THEN** its abandon count is reported as not measured rather than as zero
