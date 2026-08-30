# Server detection rules engine: compute argument position as matchable fields delta

## ADDED Requirements

### Requirement: Argument position is available as a field

The system SHALL derive from an exec event's argument vector the positional facts a detection needs, and expose them as fields a rule can match, because the Sigma format represents a command line as a single string in which argument boundaries and positions are no longer recoverable.

The system SHALL expose the verb a tool will act on, being the first non-flag token after the invocation name. A rule matching this SHALL NOT fire merely because the token it names appears somewhere in the command line, since a tool acts on its first operand and ignores the rest.

The system SHALL expose the operands that follow that verb, so a rule can ask whether any later argument matches a pattern without conflating it with the verb itself.

The system SHALL expose the environment assignments made at exec time that are visible in the argument vector, being the leading `KEY=VALUE` run. An assignment is only an assignment in leading position: the same text as a later argument is an operand of the program, not an assignment performed before it. A substring match over the whole command line cannot make that distinction, which is why the position is recovered here rather than left to the rule.

A rule matching any of these fields is portable in the sense that it is valid Sigma, but it depends on a field only this system supplies, and SHALL be reported as such rather than as standard Sigma.

#### Scenario: A rule matches the verb rather than the whole command line

- **GIVEN** a rule keyed on a tool's subcommand
- **WHEN** an event invokes that tool with the named token present but NOT as its subcommand
- **THEN** the rule does not match

#### Scenario: An operand after the verb is matchable

- **GIVEN** a rule requiring both a subcommand and a later argument matching a pattern
- **WHEN** an event supplies both
- **THEN** the rule matches

#### Scenario: A leading assignment is distinguished from a later argument

- **GIVEN** two events carrying the same assignment text, one in leading position and one as an operand of the program
- **WHEN** a rule keyed on the assignment is evaluated against both
- **THEN** it matches only the first
