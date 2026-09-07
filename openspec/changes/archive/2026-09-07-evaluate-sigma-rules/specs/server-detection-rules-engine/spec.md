# Server detection rules engine: evaluate rules written in the Sigma format delta

## ADDED Requirements

### Requirement: Rules written in the Sigma format are evaluated against a single event

The system SHALL evaluate a rule expressed as a Sigma `detection:` block, combining its named searches with its condition, against one event at a time.

The system SHALL hold no state between events while evaluating such a rule. Aggregation and correlation appear in none of the 3,141 rules of the upstream corpus, so there is no construct that requires remembering an earlier event.

The system SHALL compare values case-insensitively, as the Sigma specification defines, except under the `re` modifier, whose expression is applied verbatim so that an author who wants case-insensitivity requests it inline. Folding case there would silently widen every imported rule that relies on it.

The system SHALL support wildcards in plain values, where `*` matches any run of characters and `?` exactly one. These carry no modifier and are used by 31 of the 69 macOS rules, so a rule set without them would misread nearly half the corpus.

The system SHALL treat a backslash before `*`, `?` or a backslash as an escape, comparing the escaped character literally. 47 corpus rules escape a wildcard, and an escaped wildcard evaluated as a live one matches far more than the rule says, which surfaces as extra alerts rather than as an error.

The system SHALL fold case using Unicode simple case folding, the same equivalence the plain-value comparison uses, so that adding a wildcard to a value cannot change which characters it is considered equal to.

#### Scenario: A rule matches an event that satisfies its condition

- **GIVEN** a rule whose searches and condition describe a behaviour
- **WHEN** an event satisfying them is evaluated
- **THEN** the rule matches

#### Scenario: A filter search suppresses a match

- **GIVEN** a rule of the form `selection and not 1 of filter_*`
- **WHEN** an event satisfies both the selection and a filter
- **THEN** the rule does not match

#### Scenario: An escaped wildcard is matched literally

- **GIVEN** a rule whose value escapes a wildcard character
- **WHEN** an event carrying that literal character is evaluated
- **THEN** the rule matches, and it does not match a value where the escaped character stands for any text

#### Scenario: Values are compared without regard to case

- **GIVEN** a rule matching a value in one case
- **WHEN** an event carries that value in another case
- **THEN** the rule matches

### Requirement: An unsupported or meaningless rule construct is refused when the rule is loaded

The system SHALL refuse to load a rule that uses a modifier it does not implement, naming the field and the modifier.

The system SHALL refuse to load a rule whose condition names a search that does not exist, or whose `1 of` or `all of` pattern matches no search. Such a rule evaluates to a constant false, so it would load cleanly and then detect nothing for as long as it remained installed, which is indistinguishable from the behaviour never occurring.

The system SHALL refuse to load a rule whose field matcher combines constructs with no defined meaning together, such as a regular expression with a substring modifier, or a null value with any modifier.

The system SHALL refuse to load a rule whose search declares no values to match, since an empty list matches nothing under the default quantifier and everything under `all`.

The system SHALL refuse to load a rule whose field matcher combines two substring modifiers, or repeats one. They have no composed meaning, and letting the last one win would make two orderings of the same modifiers compile to different matchers, neither of them what the author wrote.

The system SHALL refuse to load a rule that uses a reserved Sigma key inside its detection block as though it were a search. Compiled as a search, such a key would also be swept into any quantifier, so the rule would evaluate a condition nobody wrote instead of being refused for using a construct the evaluator does not implement.

The system SHALL bound how deeply a condition may nest and refuse one that exceeds the bound. Parsing recurses once per level, so an unbounded condition would exhaust the stack and terminate the process during loading, in the very path whose contract is to return an error.

Each refusal SHALL identify the rule element at fault. Refusing at load rather than at match time is the point: an unsupported construct that was merely ignored would leave a rule that still evaluates, matching far more broadly than its author wrote, which produces confident wrong alerts rather than a visible failure.

#### Scenario: A rule using an unimplemented modifier is refused

- **GIVEN** a rule whose field matcher uses a modifier the evaluator does not implement
- **WHEN** the rule is loaded
- **THEN** loading fails, naming the field and the modifier

#### Scenario: A condition naming an undefined search is refused

- **GIVEN** a rule whose condition references a search the rule does not define
- **WHEN** the rule is loaded
- **THEN** loading fails, naming the undefined search

#### Scenario: A reserved detection key is not treated as a search

- **GIVEN** a rule whose detection block carries a reserved Sigma key alongside its searches
- **WHEN** the rule is loaded
- **THEN** loading fails, naming the unsupported construct

#### Scenario: A condition nested beyond the bound is refused

- **GIVEN** a condition nested more deeply than the parser admits
- **WHEN** the rule is loaded
- **THEN** loading fails with an error rather than exhausting the stack

#### Scenario: A quantifier matching no search is refused

- **GIVEN** a rule whose condition quantifies over a pattern matching none of its searches
- **WHEN** the rule is loaded
- **THEN** loading fails, naming the pattern

### Requirement: A rule compiles to the same evaluation on every load

The system SHALL resolve a condition's search references and quantifier patterns deterministically, independent of the order in which the rule's searches were decoded.

Go randomises map iteration, and a Sigma `detection:` block decodes to a map. Without a defined order, `all of selection_*` could resolve to a different set of searches on each start, and the resulting intermittent detection would be attributed to the rule rather than to the loader.

#### Scenario: Repeated loads of one rule resolve identically

- **GIVEN** a rule whose condition quantifies over several searches
- **WHEN** it is loaded repeatedly
- **THEN** its searches resolve in the same order every time
