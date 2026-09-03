# Rule content

## ADDED Requirements

### Requirement: Rule content is stored, and is the source the catalog loads from

The system SHALL store rule content durably, separately from the binary, and SHALL build its evaluatable rule set from that store rather than from content compiled in. Rule content SHALL be owned by a context distinct from the one that evaluates rules, which produces definitions and consumes nothing from the evaluator (ADR-0021).

Storing the content is what allows a detection to ship without a release, which is the whole purpose. It is also what makes rule content an aggregate rather than a projection of the catalog, and therefore what makes the separate ownership a boundary rather than a directory.

The stored content SHALL carry a version that changes whenever the content changes, and that version SHALL be readable without reading the content. A replica converges by noticing change, and noticing must be cheap enough to do on an interval where re-reading every document is not.

Replacing the stored content SHALL be atomic and SHALL replace it whole. Content is valid or invalid as a set: a rule removed from the source has to disappear rather than linger, and no reader may observe part of one version alongside part of another. The version SHALL advance in the same transaction, so a reader that sees a new version can only read the content that belongs to it.

The stored content SHALL be read back byte-identically, under the same identity the loader reads it by, so that storing content cannot change which detections run. That identity SHALL be the document's path, because rule identity is derived from it and collisions are detected by it before anything is parsed.

#### Scenario: The catalog loads the stored content

- **GIVEN** rule content in the store
- **WHEN** the rule set is built
- **THEN** it is built from the stored content
- **AND** the rules it yields are the same, and in the same order, as loading that content from the binary would give

#### Scenario: Replacing content removes what is no longer in it

- **GIVEN** stored content holding a rule that the replacement does not
- **WHEN** the content is replaced
- **THEN** that rule is no longer in the store
- **AND** the version has advanced

#### Scenario: The version is readable without reading the content

- **GIVEN** stored content
- **WHEN** a replica checks for change
- **THEN** it can read the version alone

### Requirement: An unavailable or unusable store leaves detections running

The system SHALL continue evaluating detections when the stored content cannot be used, and SHALL fall back to the content compiled into the build, which is the same content the store would have been seeded with.

A system that is already evaluating content SHALL keep evaluating it when new content cannot be used, and SHALL NOT record that content's version. Not recording it is what lets the system adopt the content as soon as it is corrected, since the poll keeps seeing a difference.

This leaves a divergence that is stated here rather than hidden. A replica that RESTARTS while unusable content is stored has no set in force to keep, so it falls back to the content compiled into its build and evaluates something different from its peers until the content is corrected. Making every replica adopt its build's content instead does not fix this and makes it worse: replicas part-way through a rolling deployment carry DIFFERENT built-in content, so they would record one version against different rules and report agreement they do not have. The condition is prevented upstream, by refusing content that cannot run before it is stored, rather than reconciled afterwards.

A deployment whose store is empty, unreachable, or holding content that fails to load SHALL therefore behave as it did before rule content was stored. The alternative is a server that starts with no detections because of a storage problem, which trades a bounded loss of the ability to change rules for an unbounded loss of the rules themselves.

Falling back for a REASON SHALL be reported. An empty store SHALL NOT be reported as a problem, because it is the expected state of a deployment that has not been seeded yet.

#### Scenario: Content that fails to load does not stop detection

- **GIVEN** stored content that cannot be loaded
- **WHEN** the rule set is built
- **THEN** the rules compiled into the build are evaluated instead
- **AND** the reason is reported

#### Scenario: An unseeded store is not an error

- **GIVEN** a store holding no content
- **WHEN** the rule set is built
- **THEN** the rules compiled into the build are evaluated
- **AND** nothing is reported as wrong

#### Scenario: A store that cannot be read keeps the set in force

- **GIVEN** a running system evaluating content it loaded successfully
- **WHEN** a later attempt to READ that content fails
- **THEN** the rule set already in force continues to be evaluated, unchanged
- **AND** the version it was built from is not advanced, so the next attempt retries

#### Scenario: Unusable stored content leaves the running set alone

- **GIVEN** a running system evaluating content it loaded successfully
- **WHEN** stored content is read successfully but yields no runnable rules, whether because it is empty, because it does not parse, or because every rule in it is refused
- **THEN** the rule set already in force continues to be evaluated
- **AND** that content's version is NOT recorded, so the corrected content is adopted when it arrives
- **AND** the condition is reported

#### Scenario: A system starting up has no running set to keep

- **GIVEN** stored content that yields no runnable rules, and a system with nothing yet loaded
- **WHEN** it builds its rule set
- **THEN** it evaluates the content compiled into the build, whether the content is empty or every rule in it is refused
- **AND** the two cases behave identically, because they are the same condition reached by different routes

### Requirement: Seeding never overwrites content that is already there

The system SHALL seed the store from the content compiled into the build only when the store holds no content. It SHALL NOT seed based on a comparison between the build's content and the stored content.

The distinction is what keeps authored content safe. Content in the store can be edited, so a seed that ran whenever the build looked newer would replace an operator's rules with the vendored set on the next restart. An empty store is the only state in which seeding is certainly not destroying something.

Seeding SHALL be safe to attempt on every start and on every replica, and a failure to seed SHALL NOT prevent the system from starting.

#### Scenario: An empty store is seeded

- **GIVEN** a store holding no content
- **WHEN** the system starts
- **THEN** the store holds the content compiled into the build

#### Scenario: A store holding content is left alone

- **GIVEN** a store holding content that differs from the build's
- **WHEN** the system starts again
- **THEN** the stored content is unchanged

### Requirement: A running server picks up changed content

The system SHALL adopt content published while it is running, without a restart. Each replica SHALL converge on the published content on its own, and SHALL do so by polling a version counter rather than by re-reading the content itself.

Polling the counter is what makes this affordable. The compiled rule set is derived state that every replica builds for itself, so a publish on one replica is invisible to its peers until each re-reads (ADR-0010), and a poll that re-read, parsed and compiled the whole corpus every interval would spend the cost of a publish on every replica continuously. Reading a single-row counter and comparing it against the version the loaded set was built from confines that cost to an actual change.

The version SHALL be read BEFORE the content, and the ordering is a correctness requirement rather than a preference. The two reads cannot be made atomic, so a publish landing between them yields a mismatched pair either way. Reading the version first pairs newer content with an older version, which the next poll sees as a difference and corrects. The reverse pairs older content with the newer version, which the next poll reads as current, leaving content in force that the system believes is up to date and nothing to correct it.

Adopting content SHALL bring every consumer derived from the rule set with it. The rule set has more than one consumer: the operator-facing catalog, the validation that rejects an exclusion naming a rule that does not exist, and the evaluation engine's own compiled indices. A consumer left holding a set built from withdrawn content produces no error of its own, so this is stated as a requirement rather than left to each call site: the catalog would list rules that are never evaluated, and the validation would reject an exclusion for a rule that now exists.

Replacing the content SHALL advance the version counter in the same transaction that writes the content, so that no reader can observe one generation's content under another generation's number.

A replica that has just started SHALL NOT assume the set it built is current. It has content but not the version that produced it, so its first poll SHALL adopt the stored generation and record its version, rather than treating an unknown version as a match. Assuming currency would leave a replica that started during a publish serving the older content until the NEXT publish, which is indistinguishable from working correctly.

#### Scenario: Content published elsewhere is picked up without a restart

- **GIVEN** two replicas evaluating the same stored content
- **WHEN** one of them publishes different content
- **THEN** the other adopts it without being restarted
- **AND** the replica that has not yet re-read continues to evaluate what it loaded, because the compiled set is per-replica

#### Scenario: An unchanged version does not re-read the content

- **GIVEN** a replica whose loaded content is current
- **WHEN** it polls for changes
- **THEN** it reads only the version counter
- **AND** the content is neither re-read nor recompiled

#### Scenario: The version is read before the content

- **GIVEN** content being adopted
- **WHEN** the version and the content are read
- **THEN** the version is read first, so that content newer than the version it is stamped with is corrected by the next poll

#### Scenario: A replica adopts stored content on its first poll

- **GIVEN** a replica that has just started and built a rule set
- **WHEN** it polls for changes for the first time
- **THEN** it adopts the stored content and records the version that produced it
- **AND** it does not treat the set it started with as already current

#### Scenario: The rule set in force is replaced wholesale

- **GIVEN** a rule set being adopted
- **WHEN** it is put in force
- **THEN** every consumer derived from the rule set is rebuilt from it
- **AND** no consumer continues to answer from the previous set
