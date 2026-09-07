# Tasks

## 1. Drop the claim

- [x] 1.1 Declare no technique, and say in the code why the absence is the mapping rather than an omission.
- [x] 1.3 Return an empty slice, not nil: the interface states that contract for "no mapping" and the other unmapped rule follows it.
- [x] 1.4 Take the technique out of the alert TEXT too. It is copied onto the alert verbatim, so the structured removal alone left the claim exactly where an analyst reads it.
- [x] 1.2 State in the requirement what declaring a technique asserts, so the next rule faces the question rather than copying a neighbour.

## 2. Check the premise before repeating it

- [x] 2.1 Verify where the claim actually surfaced. The coverage-export half the issue is about was already closed by the rule's health-signal classification; what remained was the alert row, because the finding declares no techniques and persistence falls back to the rule's list.

## 3. Tests

- [x] 3.1 Pin the empty mapping deliberately, saying what would have to be true to earn one back, rather than editing the old assertion to match the code.
- [x] 3.2 Assert the FINDING carries none either, so nothing downstream can stamp one from a source the rule does not control.
- [x] 3.4 Assert the description names none, and assert the empty slice as EQUAL to `[]string{}` rather than merely empty, so nil cannot pass.
- [x] 3.5 Assert the technique-id SHAPE in the prose rather than the one that was removed, so a later edit cannot add a different one and stay green.
- [x] 3.6 Cover the persisted ALERT ROW end to end, not just the rule: a unit test on the rule cannot reach the fallback that stamps the row.
- [x] 3.3 Mutation-test: restoring the technique fails.
