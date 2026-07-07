# Tasks

## 1. Conceal the email in the bar

- [x] 1.1 Remove the inline email from the account-menu trigger; keep the avatar initial and the break-glass badge.
- [x] 1.2 Add an `aria-label` to the trigger so it keeps an accessible name without visible text.
- [x] 1.3 Keep the email in the opened dropdown header (intentional reveal).
- [x] 1.4 Drop the now-unused trigger email style.

## 2. Tests

- [x] 2.1 Assert the email is absent from the collapsed menu and present after opening.
- [x] 2.2 Retarget the trigger queries to the new accessible name.
