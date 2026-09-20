# SSO sign-in sets the operator's role from their IdP groups

Issue #136. Every SSO operator landed in the default role, and an administrator then changed it by hand in the Users page. Enterprises manage who is an admin in their identity provider, and the two drift: removing someone from the admin group at the IdP left them an EDR admin.

## What changes

- **The Single sign-on configuration gains a groups claim and group mappings.** The groups claim names the ID-token claim that lists the operator's groups (for Okta, `groups`); each mapping gives a group a role. The admin API reads and writes both, validates them (a role among analyst, senior analyst, auditor and admin, never super admin; no group twice; a claim only with mappings), and the SSO configuration audit row records them. They are stored in `oidc_config`.
- **Every SSO sign-in sets the role from the groups.** The operator holds the most privileged mapped role among their groups, ranked the way the Users page already ranks roles, or the default role when none of their groups is mapped. It applies to new, existing and adopted pre-provisioned accounts, and replaces a role an administrator set by hand. A change is audited as a role binding create or update with source `oidc.groups` and the matched groups.
- **Three exceptions.** A super admin keeps their role, since no mapping can grant it. A user whose account is not active keeps theirs. The last active admin keeps their role rather than leave the deployment with no administrator; the sign-in succeeds and a warning is logged.
- **Without a groups claim nothing changes**: new accounts take the default role and sign-in never changes a role.

- **Docs.** `docs/okta-setup.md` describes adding the groups claim in Okta and saving the mapping, and the changelog announces it.

- **The Single sign-on page edits the mapping.** A Group to role mapping card takes the groups claim, a checkbox that requests the `groups` scope (Okta sends the claim only then), and a list of groups with roles to add and remove. The page refuses a claim without mappings or mappings without a claim.

## Out of scope

- Denying sign-in to an operator in no mapped group.
- Nested claim paths (such as Keycloak's `realm_access.roles`), and groups delivered only by the userinfo endpoint or by an overage reference (Entra ID).
