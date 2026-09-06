# Tasks

## 1. Report the consequence the stage actually has

- [x] 1.1 Give the stage a named type with a constant per call site, so the two cannot be transposed silently by a typo.
- [x] 1.2 Select the consequence from the stage: a process-graph gap for the builder, an incomplete rule evaluation for detection.
- [x] 1.3 Keep the log message fixed and carry the consequence on an attribute, so the line stays greppable.
- [x] 1.4 Correct the metric description and the port documentation, which carried the same unconditional claim.

## 2. Tests

- [x] 2.1 Assert the detection stage does NOT claim a process-graph gap, which is the defect this fixes.
- [x] 2.2 Assert the builder stage still does, so the fix is not "stop saying anything".
- [x] 2.3 Assert the message is constant across stages, since that is what keeps the record greppable.
- [x] 2.4 Mutation-test: restoring the unconditional claim, and swapping the detection wording for "never evaluated", are both caught.
