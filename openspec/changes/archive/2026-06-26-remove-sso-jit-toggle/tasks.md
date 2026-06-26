# Remove the JIT provisioning toggle from the SSO settings page: tasks

## 1. UI

- [x] Remove the `<Toggle>` for JIT provisioning from `SSOSettings.tsx`, drop the now-unused `Toggle` import, `jitEnabled` form field, and the `&__jit` flex layout rule.
- [x] Rewrite the help text to drop the invite reference: "Anyone who signs in through the provider is auto-created and given the default role."
- [x] Always send `jit_enabled: true` on save.
- [x] Add password-manager opt-out attributes to the client-secret field (`data-1p-ignore`, `data-form-type="other"`, `data-lpignore`, `data-bwignore`, `autocomplete="off"`) so no "Save login" prompt fires on save.

## 2. Tests

- [x] Update `SSOSettings.test.tsx`: assert no JIT switch is rendered and that save always sends `jit_enabled: true`.
- [x] Assert the client-secret field carries the password-manager opt-out attributes.

## 3. Spec + traceability

- [x] `sso-configuration` spec: MODIFIED "The Single sign-on admin settings page" to drop the JIT toggle from the rendered controls, note the secret field opts out of password-manager capture, and add scenarios for both.
- [x] spectrace markers for the new scenarios referenced from the UI test.

## 4. Docs

- [x] `docs/okta-setup.md` and `CHANGELOG.md`: drop the JIT toggle from the SSO settings-page description; state JIT is always on.
