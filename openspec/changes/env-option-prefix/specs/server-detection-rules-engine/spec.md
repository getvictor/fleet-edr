# Server detection rules engine: env's option prefix delta

## MODIFIED Requirements

### Requirement: Argument position is available as a field

The system SHALL expose, for an exec event, the environment assignments made at exec time that are visible in the argument vector, separately from the arguments themselves.

The distinction is what the field exists for. `VAR=x /bin/true` and `/bin/true VAR=x` join to different command lines but carry the same assignment text, and only the first is an injection; a substring match over the joined command line is exactly the operation that discards that difference.

For an invocation of `env`, the assignments SHALL be the run of `KEY=VALUE` tokens that follows env's own OPTIONS, ending at the first token that is not an assignment, which is the command env will run. An option ahead of the assignments SHALL NOT end the run: an option is not the command, and treating it as one hid every assignment written behind it.

An option's OPERAND SHALL NOT be read as an assignment. The variable named by an unset is the opposite of an injection, and reporting `env -u VAR prog` as assigning VAR would invert what the event says.

For any other executable the assignment SHALL be the first argument alone, which is the shell's `VAR=value cmd` form.

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
