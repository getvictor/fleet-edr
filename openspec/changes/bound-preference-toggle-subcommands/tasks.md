# Tasks

## 1. Bound the round-trip

- [x] 1.1 Add `PreferencesLatch` so the completion handler and the watchdog cannot both report.
- [x] 1.2 Add `preferencesTimeoutMessage` naming the subcommand, the bound, and the operator's next step.
- [x] 1.5 Size the bound against the consent prompt, measured on edr-dev, rather than against a hang.
- [x] 1.3 Arm a watchdog on each of the four toggle subcommands.
- [x] 1.4 Route the toggles' terminal paths through a `Never`-returning `finishToggle` so no error branch can fall through.

## 2. Test

- [x] 2.1 Exactly one of `complete()` and `expire()` wins, including under concurrent claims.
- [x] 2.2 The timeout message names the subcommand, the bound, and the console-session remedy.
- [x] 2.3 Mutation-test the latch, the message, and the bound's floor and ceiling.
- [x] 2.5 Claim the outcome BEFORE reporting it, and test the ordering: caught in review, and unit tests could not see it while the sequencing lived in main.swift.
- [x] 2.4 Measure both DNS toggles on edr-dev over SSH with no console session.
