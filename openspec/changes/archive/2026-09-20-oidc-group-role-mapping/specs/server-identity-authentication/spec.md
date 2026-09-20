## ADDED Requirements

### Requirement: SSO sign-in maps IdP groups to a role

When the stored OIDC configuration names a groups claim, every successful OIDC sign-in SHALL set the operator's single deployment-wide role from the groups that claim lists in the verified ID token. The role SHALL be the most privileged role the configured mapping gives any listed group, ranked `super_admin`, `admin`, `senior_analyst`, `analyst`, `auditor` from most to least privileged, and the configured default role when no listed group is mapped, including when the token carries no such claim. A group SHALL match a mapping only by its exact name. The claim SHALL be read as a JSON array of group names or as a single group name. This SHALL apply at every sign-in, to a newly provisioned account, an existing one, and an adopted pre-provisioned one, and SHALL replace a role an administrator set by hand, so the identity provider remains the source of truth. A change to an existing account's role SHALL be recorded as a role binding audit row (`authz.role_binding.update`, or `authz.role_binding.create` when the user held no role) attributed to the system principal, carrying the previous and new role, `source` `oidc.groups`, and the mapped groups that matched; a new account's mapped role SHALL be recorded, with the matched groups, on its `user.created` row. Three users SHALL keep their role: one who holds `super_admin`, which no mapping can grant; one whose account is not active; and the last active admin, when the mapped role would leave the deployment without one, in which case the sign-in SHALL still succeed. A role change SHALL be decided again together with the write, so a `super_admin` grant or a disable committed after the sign-in first read the account is not overwritten. When no groups claim is configured, sign-in SHALL NOT change an existing user's role.

#### Scenario: Joining a mapped admin group makes the operator an admin

- **GIVEN** group to role mapping maps the group `edr-admins` to `admin`, and an SSO operator who holds `analyst`
- **WHEN** the operator signs in with an ID token whose groups claim lists `edr-admins`
- **THEN** the operator holds exactly the `admin` role
- **AND** an `authz.role_binding.update` audit row records the change from `analyst` to `admin` with source `oidc.groups` and the matched group

#### Scenario: Leaving the group returns the operator to the default role

- **GIVEN** group to role mapping maps `edr-admins` to `admin`, the default role is `analyst`, and an SSO operator who holds `admin` (with another active admin)
- **WHEN** the operator signs in with an ID token whose groups claim no longer lists `edr-admins`
- **THEN** the operator holds exactly the `analyst` role

#### Scenario: The most privileged mapped role wins

- **GIVEN** group to role mapping maps `edr-auditors` to `auditor` and `edr-senior` to `senior_analyst`
- **WHEN** an operator signs in with an ID token whose groups claim lists both groups
- **THEN** the operator holds exactly the `senior_analyst` role

#### Scenario: A new account is created in its mapped role

- **GIVEN** just-in-time provisioning is enabled, group to role mapping maps `edr-senior` to `senior_analyst`, and no account exists for the subject
- **WHEN** the subject signs in with an ID token whose groups claim lists `edr-senior`
- **THEN** the new account is bound to `senior_analyst` rather than the default role

#### Scenario: A super admin keeps their role

- **GIVEN** group to role mapping is configured and an SSO operator who holds `super_admin`
- **WHEN** the operator signs in with an ID token whose groups map to `analyst`
- **THEN** the operator still holds `super_admin` and no role binding audit row is recorded

#### Scenario: A disabled operator's role is not changed

- **GIVEN** group to role mapping is configured and an SSO operator who holds `analyst` and whose account is disabled
- **WHEN** an OIDC sign-in for that operator carries a group mapped to `admin`
- **THEN** the operator still holds `analyst` and no role binding audit row is recorded

#### Scenario: The last active admin keeps their role and still signs in

- **GIVEN** group to role mapping is configured and the only active admin is an SSO operator
- **WHEN** that operator signs in with an ID token whose groups map to `analyst`
- **THEN** the sign-in succeeds and the operator still holds `admin`

#### Scenario: Without a groups claim, sign-in leaves the role alone

- **GIVEN** no groups claim is configured and an SSO operator whose role an administrator set to `senior_analyst`
- **WHEN** the operator signs in
- **THEN** the operator still holds `senior_analyst`

## MODIFIED Requirements

### Requirement: Just-in-time provisioning of unknown SSO users

The system SHALL provision a user account on first successful Okta login when `auth.oidc.allow_jit_provisioning` is enabled and no identity row exists for the incoming `(provider, subject)` pair. The newly-created user SHALL be bound to the deployment's configured default JIT role at the deployment-wide scope (the seeded `analyst` role by default, overridable to another seeded role through the stored OIDC configuration's default-role field set via the Single sign-on admin API). When the stored OIDC configuration names a groups claim, the new user SHALL instead be bound to the role that group to role mapping gives their groups, as the requirement on mapping IdP groups to a role describes; otherwise it MUST NOT take a role from claims. The provisioning SHALL emit an audit row with action `user.created`. When `allow_jit_provisioning` is disabled, an unknown subject SHALL be denied with an audit row whose reason is `oidc.unknown_subject`.

#### Scenario: First Okta login auto-provisions an analyst

- **GIVEN** OIDC is enabled with `allow_jit_provisioning = true` and no identity row for the incoming subject
- **WHEN** the callback handler processes a verified ID token
- **THEN** the server inserts a `users` row with `password_hash = NULL` and `is_breakglass = 0`, an `identities` row keyed by `(provider, subject)`, and a `role_bindings` row to the seeded `analyst` role at the deployment-wide scope
- **AND** the audit log records `action='user.created'` with the actor identity and the resulting user id

#### Scenario: Unknown subject is rejected when JIT is disabled

- **GIVEN** OIDC is enabled with `allow_jit_provisioning = false` and no identity row for the incoming subject
- **WHEN** the callback handler processes a verified ID token
- **THEN** the server returns a non-2xx error response and does not create a user
- **AND** the audit log records the decision with reason `oidc.unknown_subject`
