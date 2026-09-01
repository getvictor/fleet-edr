# Observability instrumentation

## ADDED Requirements

### Requirement: Recorded monitor-match counts are readable per rule

The system SHALL expose the recorded monitor-mode match counts through the operator API, aggregated per rule over a caller-specified window, so the evidence for promoting a rule is available where the promotion is made rather than only in a metrics backend.

Each rule's entry SHALL report the total matches in the window, the number of distinct hosts that contributed, and when the rule most recently matched. The three answer different halves of one decision: equal totals mean opposite things depending on whether they came from one host, which calls for an exclusion, or from many, which means the rule itself is too broad, and a rule that matched heavily but not recently is a third case again.

A rule that matched nothing in the window SHALL be absent from the response rather than present with a zero, and the response SHALL be an empty list rather than null when no rule matched.

The window SHALL default when unspecified and SHALL be capped, and the response SHALL state the window it covers, because the cap means a caller can receive a narrower window than it asked for and would otherwise describe the number to an operator as covering a period it does not. The cap SHALL be the deployment's own counter retention, not a fixed constant: the counters are pruned with the configured retention, so a fixed cap would report a window over rows that retention has already deleted. The default SHALL be capped by the same bound, since a deployment retaining less than the default would otherwise answer an unspecified window with a period it cannot cover. A window that is not a positive whole number SHALL be rejected rather than defaulted, since answering a different question than the one asked is worse than answering none, and a supplied-but-empty value is a malformed value rather than an omission.

A failure to read SHALL be reported as an error rather than as an empty result, and SHALL be distinguished from a rule having matched nothing wherever the counts are presented. An empty result reads as a quiet rule, which is the reading that gets a noisy rule promoted, so rendering a failed read as absence turns an outage into fleet-wide evidence that every rule is quiet.

The reported figure SHALL be presented as an approximation of what promoting the rule would produce, never as a count of it. It counts matches, while alerts deduplicate on (host, rule, subject) permanently, so it is biased upward by repeated subjects and downward by the recorder's documented losses.

#### Scenario: Counts are readable per rule over a window

- **GIVEN** recorded monitor matches for two rules, one concentrated on a single host and one spread across several
- **WHEN** the counts are read for a window covering them
- **THEN** each rule reports its total matches, its distinct host count, and its most recent match
- **AND** a rule whose matches all fall outside the window is absent rather than reported as zero
- **AND** each rule's most recent match is reported, so a rule that matched heavily and has since gone quiet is distinguishable from one still matching

#### Scenario: A failed read is not presented as an absence of matches

- **GIVEN** a reader whose attempt to load the counts fails
- **WHEN** the counts are presented
- **THEN** they are shown as unavailable rather than as no matches recorded
- **AND** the promotion control remains usable

#### Scenario: The window is stated and bounded

- **GIVEN** a caller requesting a window
- **WHEN** the request exceeds the cap
- **THEN** the response covers the capped window and states which window it covers
- **AND** a window that is not a positive whole number is rejected

#### Scenario: The cap follows the deployment's retention

- **GIVEN** a deployment retaining fewer days of counters than the default window
- **WHEN** the counts are read without a window, and again with one longer than retention
- **THEN** both are served at the retention, and both report that as the window covered
- **AND** a deployment that has disabled pruning is still bounded by the fixed maximum
