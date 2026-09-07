# Observability instrumentation

## ADDED Requirements

### Requirement: Evaluation statistics are readable per rule

The system SHALL expose the recorded per-rule evaluation statistics through the operator API and present them beside the rule they describe, aggregated over a caller-specified window, so a slow or churning rule is identifiable where its tuning is done rather than only in a metrics backend.

This is the consumer half the durable-recording requirement deliberately left to whatever surface presents the figures. A record no interface reads answers nothing: at a thousand rules, the rule holding up the drain loop cannot be found by reading logs, and it is invisible to the match counts, because a rule can be perfectly quiet and still be the expensive one.

Each rule's entry SHALL report its evaluation attempts, how many of those ended without a decision, the mean time per attempt, and the worst single attempt. The mean and the maximum are both required because either alone misleads: a mean hides the rule that is usually fast and occasionally terrible, and a maximum alone promotes the rule that had one bad batch over the one that is expensive every time.

The mean SHALL be computed from the recorded totals rather than stored, so it stays correct as the window widens and as retention prunes days out of it.

Attempts SHALL be reported as attempts, not as logical batches, matching how they are recorded. A replayed batch really did evaluate again. The derived mean is unaffected, since the time inflates by the same factor, but a reader comparing attempt counts between rules is comparing work performed rather than events seen, and the surface SHALL say so rather than let the count read as a fire count.

A rule that did not evaluate in the window SHALL be absent from the response rather than present with zeros, and the response SHALL be an empty list rather than null when no rule evaluated.

The window SHALL default when unspecified and SHALL be capped at the deployment's own retention, and the response SHALL state the window it covers, for the same reasons the match-count read does: the cap can make the served window narrower than the one requested, and a figure labelled with a period it does not cover is a misreport rather than an approximation. A window that is not a positive whole number SHALL be rejected rather than defaulted.

A failure to read SHALL be reported as an error rather than as an empty result, and SHALL be distinguished from a rule having no recorded evaluations wherever the statistics are presented. An empty result reads as a cheap rule, so rendering a failed read as absence tells an operator hunting the slow rule that there isn't one. A surface that reports the statistics as unavailable SHALL NOT go on ordering or ranking by the ones it read before, since a ranking an operator can act on is not distinguishable from a current one by looking at it.

This read and the match-count read SHALL fail independently. They describe different populations over different questions, and a rule that never matches still evaluates, so one failing SHALL NOT suppress the other.

#### Scenario: Statistics are readable per rule over a window

- **GIVEN** recorded evaluations for two rules, one cheap and frequent and one expensive
- **WHEN** the statistics are read for a window covering them
- **THEN** each rule reports its attempts, its undecided attempts, its mean time and its worst attempt
- **AND** a rule whose evaluations all fall outside the window is absent rather than reported as zero

#### Scenario: A failed read is not presented as no cost

- **GIVEN** a reader whose attempt to load the statistics fails
- **WHEN** the statistics are presented
- **THEN** they are shown as unavailable rather than as no evaluations recorded
- **AND** the rule's tuning controls remain usable

#### Scenario: One read failing does not suppress the other

- **GIVEN** a surface presenting both the evaluation statistics and the monitor-match counts
- **WHEN** one of the two reads fails and the other succeeds
- **THEN** the failed one is shown as unavailable
- **AND** the one that succeeded is still presented

#### Scenario: The window is stated and bounded

- **GIVEN** a caller requesting a window longer than the deployment retains
- **WHEN** the statistics are read
- **THEN** the response covers the retained window and states which window it covers
- **AND** a window that is not a positive whole number is rejected
