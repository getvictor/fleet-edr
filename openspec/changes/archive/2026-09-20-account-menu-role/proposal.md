# The account menu names the session's role

Issue #1038. The account menu shows the email's initial on its trigger and a Break-glass badge for a break-glass session. Nothing in the product tells an operator which role their session carries short of opening Admin settings, which most roles cannot reach. An operator refused an action cannot say what they currently hold. `2026-06-02-add-user-management` specified the role and sign-in method in the account menu, and the archive dropped it before it was built (#905).

## What changes

- **`GET /api/session` returns `roles`**: the ids of the operator's deployment-wide role bindings, sorted. These are the bindings `permissions` is already computed from.
- **The account menu dropdown names them** under the email: `Role: Senior analyst`, or `Role: none`. It also names the sign-in method: `Signed in with SSO` for an OIDC session, since SSO is any OIDC provider, and `Signed in with break-glass`. The trigger is unchanged and still conceals the identity until opened.
- **One set of role labels.** Users, Service accounts and the account menu share `ui/src/roles.ts` instead of each keeping its own.

The archive-verify exception for `web-ui/account-menu-surfaces-role-and-authentication-method` names #1038. When this change is archived at release, that entry becomes `covered_by` the requirement below.
