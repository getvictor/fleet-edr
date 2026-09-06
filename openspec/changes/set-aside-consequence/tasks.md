# Tasks

## 1. Report the consequence the stage actually has

- [x] 1.1 Give the stage a named type with a constant per call site, so a misspelled stage fails to compile rather than reporting a wrong consequence. Transposing the two constants still compiles, which is what 2.5 covers.
- [x] 1.2 Select the consequence from the stage: a process-graph gap for the builder, an incomplete rule evaluation for detection.
- [x] 1.3 Keep the log message fixed and carry the consequence on an attribute, so the line stays greppable.
- [x] 1.4 Correct every other place describing what a set-aside costs, found by grepping the claim rather than by taking a reviewer's list: the metric description and its rationale, the recorder, the detection port, the queue-prune runner, the event-log port, and the store.
- [x] 1.5 Leave the two statements about the STALL alone. An unbounded retry does take the whole host out of the graph, because nothing newer is ever claimed; that claim is unconditional and true, and rewording it would trade one wrong statement for another.

## 2. Tests

- [x] 2.1 Assert the detection stage does NOT claim a process-graph gap, which is the defect this fixes.
- [x] 2.2 Assert the builder stage still does, so the fix is not "stop saying anything".
- [x] 2.3 Assert the message is constant across stages, since that is what keeps the record greppable.
- [x] 2.4 Mutation-test: restoring the unconditional claim, and swapping the detection wording for "never evaluated", are both caught.
- [x] 2.5 Drive both production call sites, so transposing the two stage constants there fails a test rather than only being narrowed by the type.
- [x] 2.6 Assert the log message by equality, not containment, so a stage-specific suffix cannot be added without failing.
