# Tasks

- [x] Store the groups claim and group mappings in `oidc_config`, and read and write them through the SSO admin API with validation and audit.
- [x] Read the groups claim from the verified ID token and choose the most privileged mapped role, or the default role.
- [x] Bind the mapped role on JIT creation, and set it at every other sign-in, keeping a super admin's role and the last active admin's role, and audit a change with source `oidc.groups`.
- [x] Tests referencing the delta's scenarios; mutation-check them.
- [x] Document the Okta groups claim and the mapping in `docs/okta-setup.md`, and add a changelog entry.
- [x] QA a sign-in against dex with groups on the dev server.
- [ ] Console editor for the claim and mappings (second change).
