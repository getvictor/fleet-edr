# Keep the signed-in email out of the always-visible bar

## Why

The top-right account menu rendered the signed-in user's full email (e.g. `admin@fleet-edr.local`) inline in the always-visible nav bar. On a shared screen or a screen-share that is a passive identity leak: anyone glancing at the display learns the operator's account without any action. The email is only needed to confirm "who am I signed in as", which is an intentional check, not something to broadcast continuously.

## What changes

- The account-menu trigger shows only the avatar initial (and the break-glass badge when present); the email is no longer rendered in the always-visible bar.
- The signed-in email is still available in the account-menu dropdown, revealed when the operator opens it.
- The trigger carries an `aria-label` so it stays named for assistive tech now that its visible text is gone.
- The break-glass badge on the trigger is restyled to a solid gold pill with dark text so it is readable on the dark nav bar (the old translucent-gold fill with brown text was tuned for a light background and was nearly invisible against the navy).

## Impact

- Affected specs: `web-ui` (ADDED: Account menu conceals the signed-in identity until opened).
- Affected code: `ui/src/components/ui/AccountMenu.tsx` and its styles/tests.
- No server, wire-format, or persistence change; no change to what data the session carries.
