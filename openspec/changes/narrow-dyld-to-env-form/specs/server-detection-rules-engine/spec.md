# Server detection rules engine: narrow the dylib-injection rule delta

## MODIFIED Requirements

### Requirement: Argument position is available as a field

The system SHALL derive from an exec event's argument vector the positional facts a detection needs, and expose them as fields a rule can match, because the Sigma format represents a command line as a single string in which argument boundaries and positions are no longer recoverable.

The system SHALL expose the verb a tool will act on, being the first non-flag token after the invocation name. A rule matching this SHALL NOT fire merely because the token it names appears somewhere in the command line, since a tool acts on its first operand and ignores the rest.

The system SHALL expose the operands that follow that verb, so a rule can ask whether any later argument matches a pattern without conflating it with the verb itself.

The system SHALL expose the environment assignments made at exec time that are visible in the argument vector. Those are the assignments an `env` invocation performs, and ONLY those. A shell's `VAR=value cmd` form is not visible in an argument vector at all, because a shell applies it without passing it as an argument, so the system SHALL NOT report the first argument of a non-`env` invocation as an assignment; reporting it would advertise coverage no agent can supply. Within an `env` invocation an assignment is only an assignment in leading position: the same text as a later argument is an operand of the program, not an assignment performed before it. A substring match over the whole command line cannot make that distinction, which is why the position is recovered here rather than left to the rule.

For an invocation of `env`, the assignments SHALL be the run of `KEY=VALUE` tokens that follows env's own OPTIONS, ending at the first token that assigns nothing, which is the command env will run. An option ahead of the assignments SHALL NOT end the run: an option is not the command, and treating it as one hid every assignment written behind it.

The end of that run SHALL be decided by whether a token assigns at all, and NOT by whether the name it assigns is one a shell would accept. env applies any nonempty name, so a token such as `2+2=4` is an assignment env performs and the run continues past it; ending the run there would hide an injection written behind it. Only WELL-FORMED assignments SHALL be reported, so the narrower test governs the reported set and the wider one governs the boundary.

An assignment whose NAME is empty is the exception, and it ends more than the run: env cannot set it, exits before executing anything, and therefore applied none of the assignments around it. Such an invocation SHALL report no assignments at all. The discriminator is emptiness rather than shell-legality, which is why this does not reopen the boundary above.

An option's OPERAND SHALL NOT be read as an assignment. The variable named by an unset is the opposite of an injection, and reporting `env -u VAR prog` as assigning VAR would invert what the event says. An operand SHALL be taken from the remainder of its own token when there is one and from the next argument otherwise, so that the trailing characters of an attached operand are not themselves read as further options.

An invocation SHALL report no assignments when the argument vector after env's options no longer describes what env applied. Three cases, and in each one the safe direction is the same: an option env does NOT have, because env exits without executing the command and performs none of them; the option that suppresses running a command at all, which env refuses to combine with one; and the option carrying a whole command line as its value, since env re-splits that value and the command it names may consume the tokens that follow as its own arguments.

That asymmetry is the reason the rule SHALL prefer reporting nothing in all three. Reporting nothing risks MISSING an injection, which another detection may still catch. Reporting the run risks FABRICATING one, sending an analyst after an event that did not happen, and this field feeds a high-severity rule.

An option's OPERAND SHALL also be judged where env decides it STATICALLY. An unset of a name env cannot unset, being empty or containing an assignment separator, makes env exit before executing anything, so the assignments after it were never applied. An operand-taking option with no operand at all likewise makes env exit.

The preference for a miss over a fabrication SHALL NOT extend to an operand whose validity depends on the HOST rather than on the argument vector. The working-directory option is refused only when the directory does not exist, which is a property of the host at execution time and usually holds, so treating a named directory as unusable would let an attacker suppress a high-severity finding with one flag. A miss the ATTACKER chooses is worse than a fabrication the environment causes by accident, which is why the preference inverts for exactly this case and no other.

That exception is per VALUE and not per option. An EMPTY working directory is refused whatever the host looks like, so it is decided like any other statically invalid operand; only a named one is left undecided.

For any other executable the system SHALL report no assignments. The invocation name SHALL NOT be scanned for env either, since that is env's own name and not an assignment it performs.

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

#### Scenario: A name a shell would reject does not end the run

- **GIVEN** an exec event for env whose leading assignments include a name no shell would accept, followed by an injection assignment
- **WHEN** the assignments are read
- **THEN** the injection assignment is reported and the malformed name is not

#### Scenario: An attached operand is not read as further options

- **GIVEN** an exec event for env whose option carries its operand attached, with the operand ending in a character that is itself an option letter
- **WHEN** the assignments are read
- **THEN** the following assignment is reported rather than consumed as an operand

#### Scenario: An invocation env would refuse reports no assignments

- **GIVEN** an exec event for env carrying an option env does not have, followed by an assignment
- **WHEN** the assignments are read
- **THEN** no assignment is reported

#### Scenario: An option suppressing the command reports no assignments

- **GIVEN** an exec event for env carrying the option that refuses to run a command, followed by an assignment
- **WHEN** the assignments are read
- **THEN** no assignment is reported

#### Scenario: A command line carried as an option value reports no assignments

- **GIVEN** an exec event for env whose option value is a command line, followed by a token that looks like an assignment
- **WHEN** the assignments are read
- **THEN** no assignment is reported, because that token may be an argument of the command the value names

#### Scenario: An unset of a name env cannot unset reports no assignments

- **GIVEN** an exec event for env unsetting a name that is empty or contains an assignment separator, followed by an assignment
- **WHEN** the assignments are read
- **THEN** no assignment is reported, because env exits before executing anything

#### Scenario: An operand whose validity depends on the host does not suppress the finding

- **GIVEN** an exec event for env whose working-directory operand names a directory, followed by an assignment
- **WHEN** the assignments are read
- **THEN** the assignment is reported, because suppressing it would be an attacker-selectable bypass rather than a protection
- **AND** an EMPTY working directory instead reports no assignments, because that one is refused whatever the host looks like

#### Scenario: An assignment with an empty name reports nothing at all

- **GIVEN** an exec event for env whose leading assignments include one with an empty name, followed by an injection assignment
- **WHEN** the assignments are read
- **THEN** no assignment is reported, because env exits before executing anything

#### Scenario: A shell-form assignment is not reported

- **GIVEN** an exec event for an ordinary binary whose first argument looks like an environment assignment
- **WHEN** the assignments are read
- **THEN** nothing is reported, because a shell applies its assignments without passing them as arguments and no agent can produce that event
