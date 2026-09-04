# Server detection rules engine: env's option prefix delta

## MODIFIED Requirements

### Requirement: Argument position is available as a field

The system SHALL derive from an exec event's argument vector the positional facts a detection needs, and expose them as fields a rule can match, because the Sigma format represents a command line as a single string in which argument boundaries and positions are no longer recoverable.

The system SHALL expose the verb a tool will act on, being the first non-flag token after the invocation name. A rule matching this SHALL NOT fire merely because the token it names appears somewhere in the command line, since a tool acts on its first operand and ignores the rest.

The system SHALL expose the operands that follow that verb, so a rule can ask whether any later argument matches a pattern without conflating it with the verb itself.

The system SHALL expose the environment assignments made at exec time that are visible in the argument vector. An assignment is only an assignment in leading position: the same text as a later argument is an operand of the program, not an assignment performed before it. A substring match over the whole command line cannot make that distinction, which is why the position is recovered here rather than left to the rule.

For an invocation of `env`, the assignments SHALL be the run of `KEY=VALUE` tokens that follows env's own OPTIONS, ending at the first token that is not an assignment, which is the command env will run. An option ahead of the assignments SHALL NOT end the run: an option is not the command, and treating it as one hid every assignment written behind it.

An option's OPERAND SHALL NOT be read as an assignment. The variable named by an unset is the opposite of an injection, and reporting `env -u VAR prog` as assigning VAR would invert what the event says.

For any other executable the assignment SHALL be the first argument alone, which is the shell's `VAR=value cmd` form. The invocation name SHALL NOT be scanned for env, since that is env's own name and not an assignment it performs.

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

#### Scenario: An option before an assignment does not hide it

- **GIVEN** an exec event for env whose arguments place an option before an assignment
- **WHEN** the assignments are read
- **THEN** the assignment is reported

#### Scenario: An option's operand is not an assignment

- **GIVEN** an exec event for env that unsets a variable by name
- **WHEN** the assignments are read
- **THEN** the unset variable is not reported as assigned

#### Scenario: An assignment after the end-of-options marker belongs to the command

- **GIVEN** an exec event for env whose end-of-options marker is followed by a token that looks like an option
- **WHEN** the assignments are read
- **THEN** that token is treated as the command rather than as an option
