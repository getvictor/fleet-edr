# Remove the JIT provisioning toggle from the SSO settings page

## Why

The Single sign-on settings page shows a just-in-time (JIT) provisioning on/off toggle whose help text reads: "When on, anyone who signs in through the provider is auto-created and given the default role. When off, an operator must be invited first." The "off" path depends on an operator invite flow that is not built yet, so turning JIT off leaves no way to provision operators at all: SSO logins would be rejected with no recourse from the UI. Offering a control whose disabled state is a dead end is a footgun, and the help text references an invite flow that does not exist.

## What changes

- The SSO settings page no longer renders the JIT provisioning toggle. JIT is always on: anyone who signs in through the provider is auto-created with the default role.
- The page's help text no longer references inviting operators. It now states only that signed-in users are auto-created with the default role.
- On save, the page always sends `jit_enabled: true`. The persisted flag and the server-side login flow are unchanged; the UI simply stops exposing a way to set it to false.
- The default-role selector (Analyst / Auditor) stays, since auto-created users still need a default role.
- The client-secret field opts out of password-manager capture. It is `type="password"` only to mask the value, but it holds an OIDC client secret (deployment config), not an account credential. Password managers classify any form with a password field as a login and pop a "Save login" prompt on save; the field now carries the per-manager opt-out attributes (`data-1p-ignore` and `data-form-type="other"` for 1Password / Dashlane, `data-lpignore` for LastPass, `data-bwignore` for Bitwarden) and `autocomplete="off"` for the browser's built-in manager.

### Not in this change

- The invite flow itself. When it lands, the toggle (and the "off" path) can be reintroduced.
- The server-side `jit_enabled` persistence and login behavior: the column, the config record, and the login flow are untouched.
