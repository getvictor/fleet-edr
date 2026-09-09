# Tasks

## 1. Replace the hover-only tooltips

- [x] 1.1 Add one disclosure control shared by both abbreviated columns.
- [x] 1.2 Keep the abbreviated value as the visible content.
- [x] 1.3 Keep the full sentence in the document at all times, associated with the control as its description.

## 2. Verification

- [x] 2.1 Tests for keyboard focusability, the expanded state, and the description association.
- [x] 2.2 Mutation-test the disclosure: never revealing, description detached, control reverted to a span, expanded state unexposed.
- [x] 2.3 Visual confirmation in a real browser: keyboard focus + Enter and a pointer click both expand the description from 1px to a rendered block, on both columns, on the live dev server.
