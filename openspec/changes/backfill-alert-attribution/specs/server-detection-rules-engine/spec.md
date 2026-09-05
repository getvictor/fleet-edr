# Server detection rules engine: backfill alert attribution delta

## ADDED Requirements

### Requirement: Alerts raised before attribution was recorded are credited

The system SHALL credit alerts that carry no attribution but were raised by a rule this project did not write, so the licence obligation those rules carry is met for alerts raised before attribution was recorded rather than only for later ones.

The pass SHALL run at most once per boot, on exactly one replica, and SHALL NOT block startup on becoming that replica.

It SHALL touch only alerts whose attribution is absent, so an attribution already recorded is never overwritten and repeating the pass changes nothing.

Two classes of alert SHALL NOT be credited, and both are irreversible if credited wrongly:

- An alert raised by a rule this project wrote. The absence of attribution on those rows is meaningful: it distinguishes an alert raised before attribution existed from one raised by this project, and crediting them collapses the two.
- An alert raised by a projection of an operator's own configuration, whose rule identifier names the operator's policy entry rather than a detection. Crediting those claims authorship of the operator's configuration.

The pass SHALL bound how much it rewrites in a single statement. Alerts carry no index that this predicate can use, so an unbounded rewrite would hold row locks across a full scan at start-up, on a system that may already be serving.

Alerts from a rule the deployment no longer runs SHALL NOT be credited, and that limit is stated rather than worked around: crediting them would require a record of every rule that ever shipped, and guessing an author is worse than leaving the field empty.

A failure to credit SHALL NOT prevent the system from starting or from detecting, because an unpaid credit on historical rows is not a reason to stop detecting today, and the next start retries.

#### Scenario: An uncredited alert from a vendored rule is credited

- **GIVEN** an alert raised by a rule this project did not write, carrying no attribution
- **WHEN** the pass runs
- **THEN** the alert is credited to that rule's author

#### Scenario: An alert from a rule this project wrote is left alone

- **GIVEN** an alert raised by a rule this project wrote, carrying no attribution
- **WHEN** the pass runs
- **THEN** the alert still carries no attribution, because that absence distinguishes it from one raised before attribution existed

#### Scenario: An alert from a projection is left alone

- **GIVEN** an alert raised by a projection of an operator's own configuration, carrying no attribution
- **WHEN** the pass runs
- **THEN** the alert still carries no attribution, because its rule identifier names the operator's entry rather than a detection

#### Scenario: An attribution already recorded is never overwritten

- **GIVEN** an alert already carrying an attribution
- **WHEN** the pass runs
- **THEN** that attribution is unchanged, and running the pass again changes nothing

#### Scenario: More alerts than one statement rewrites are all credited

- **GIVEN** more uncredited alerts from a vendored rule than the pass rewrites in a single statement
- **WHEN** the pass runs
- **THEN** every one of them is credited
