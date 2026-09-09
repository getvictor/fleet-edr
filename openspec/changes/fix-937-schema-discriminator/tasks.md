# Tasks

## 1. Fix the schema

- [x] 1.1 Replace `payload.oneOf` with a top-level `allOf` of `if`/`then` clauses keyed on `event_type`.
- [x] 1.2 Give every `if` a `"required": ["event_type"]` guard so it does not match vacuously on an envelope that omits the discriminator.
- [x] 1.3 Leave the payload definitions themselves untouched.

## 2. Fix the emitter the schema caught

- [x] 2.1 Emit a real UUID from `test/fakeagent`'s default `event_id` generator.

## 3. Test

- [x] 3.1 Validate one minimal envelope per event type, asserting the fixture set matches the enum exactly.
- [x] 3.2 Validate the envelopes the fake agent's shipped scenarios actually emit.
- [x] 3.3 Assert mismatched payloads are rejected.
- [x] 3.4 Assert every enum value has exactly one discriminator clause pointing at an existing definition.
- [x] 3.5 Mutation-test: restore `oneOf`, drop a clause, drop an `if` guard, revert the UUID fix, and confirm each is caught.
