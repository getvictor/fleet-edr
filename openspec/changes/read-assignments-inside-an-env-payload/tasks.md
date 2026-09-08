# Tasks

- [x] 1.1 Measure env's `-S` split against `env(1)` on macOS: whitespace, quotes, backslash escapes, `${VAR}` substitution, embedded options, and what a trailing token belongs to.
- [x] 1.2 Resolve the `-S` operand rather than discarding it, while still ending the outer run so a trailing token is never an assignment.
- [x] 2.1 Read the payload's leading assignment run through the same collector as the ordinary path, so the two cannot drift.
- [x] 2.2 Report nothing for a payload using a construct that is not emulated.
- [x] 3.1 Replace the known-gap test rather than deleting it, and cover each unemulated construct.
- [x] 3.2 Differential-check the parser against the real binary for the shapes covered.
- [x] 4.1 Restate the requirement: the command-line option value is no longer one of the report-nothing cases.
