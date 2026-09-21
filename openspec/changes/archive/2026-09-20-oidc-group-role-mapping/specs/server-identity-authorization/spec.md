## MODIFIED Requirements

### Requirement: Five seeded roles bundle permissions for the deployment

The system SHALL seed five roles at startup and SHALL keep their `is_builtin` flag set so they cannot be deleted via the admin API: `super_admin` (SSO config + every permission below), `admin` (day-to-day administration: user.read, user.invite, sso.manage, policy._, host._, alert._), `senior_analyst` (investigate + take destructive action: host.read, host.isolate, host.kill_process, host.run_script, alert._), `analyst` (investigate + comment + escalate: host.read, process.read, alert.read, alert.comment), and `auditor` (read-only including audit.read). The `sso.manage` action gates reading and mutating the deployment's stored OIDC configuration; it is held by `admin` explicitly and by `super_admin` through its wildcard grant, and no other role holds it. The break-glass user MUST be bound to `super_admin` at the deployment-wide scope. SSO-provisioned users MUST default to the configured default role (`analyst` unless an administrator changes it) at the deployment-wide scope. The system MUST NOT elevate a role from an SSO claim except through the group to role mapping an administrator configures, which can never grant `super_admin`. The `*.*` notation above (`policy.*`, `host.*`, `alert.*`) is prose shorthand for the concrete per-domain action identifiers each role is granted; the seeds expand it to explicit actions in the policy bundle, and only `super_admin` holds a literal wildcard (`*`) grant. This keeps the seeds consistent with the UI permission-set expansion requirement, which returns concrete action identifiers rather than a wildcard token.

#### Scenario: Roles are seeded on first boot

- **GIVEN** an empty `roles` table
- **WHEN** the server boots
- **THEN** exactly the five seeded roles exist with `is_builtin=1`
- **AND** the break-glass user (when present) is bound to `super_admin` at the deployment-wide scope

#### Scenario: Built-in role cannot be deleted

- **GIVEN** an authenticated `super_admin`
- **WHEN** the operator attempts to delete a role with `is_builtin=1`
- **THEN** the server returns a typed error and does not modify the role

#### Scenario: Admin holds sso.manage; analyst does not

- **GIVEN** the seeded roles
- **WHEN** the chokepoint evaluates the `sso.manage` action
- **THEN** an actor bound to `admin` or `super_admin` is allowed
- **AND** an actor bound to `senior_analyst`, `analyst`, or `auditor` is denied with reason `no_matching_rule`

### Requirement: First SSO login adopts a pre-provisioned account into its staged role

When an OIDC sign-in presents a subject with no existing identity and an explicitly verified email (the `email_verified` claim is present and true) that matches a pre-provisioned account, the system SHALL adopt that account rather than create a new one or reject the login: it SHALL link the OIDC identity to the existing user, transition the account status from `provisioned` to `active`, and retain the pre-assigned role instead of binding the default JIT role, unless the stored OIDC configuration names a groups claim, in which case the adopted account takes the role its groups map to, as for any SSO sign-in. This adoption SHALL occur regardless of whether just-in-time provisioning is enabled, because pre-provisioning is an explicit administrative staging decision. Adoption SHALL require explicit email verification, stricter than just-in-time creation, because it binds an external subject to a pre-staged and possibly elevated role: an absent `email_verified` claim SHALL NOT adopt. The status transition SHALL be the single-winner serialization point so two concurrent sign-ins for the same staged email can never both bind: at most one SHALL adopt and the other SHALL be rejected as an email conflict. An email that already belongs to an account with any identity, or to a break-glass account, SHALL still be rejected as an email conflict.

#### Scenario: A pre-provisioned operator lands in the staged role on first login

- **GIVEN** a pre-provisioned user `alice@example.com` staged into `senior_analyst` with no identity yet
- **WHEN** Alice signs in via OIDC with a verified email matching that account
- **THEN** the OIDC identity is linked to the existing account, its status becomes `active`, and she holds the `senior_analyst` role rather than the default JIT role

#### Scenario: Adoption is honored even when JIT provisioning is disabled

- **GIVEN** just-in-time provisioning is disabled and a pre-provisioned user `alice@example.com` exists with no identity
- **WHEN** Alice signs in via OIDC with a verified email matching that account
- **THEN** the account is adopted and activated rather than denied as an unknown subject

#### Scenario: An email already bound to a real account is not adopted

- **GIVEN** a user `carol@example.com` that already has an OIDC identity
- **WHEN** a different OIDC subject signs in with the verified email `carol@example.com`
- **THEN** the login is rejected as an email conflict and the existing account is unchanged

#### Scenario: An absent verification claim does not adopt

- **GIVEN** a pre-provisioned user staged into an elevated role
- **WHEN** an OIDC sign-in matches that email but omits the `email_verified` claim
- **THEN** the staged account is not adopted and keeps its `provisioned` status

#### Scenario: A second subject cannot claim an adopted staged account

- **GIVEN** a pre-provisioned account already adopted by a first OIDC subject on its first login
- **WHEN** a second, different OIDC subject signs in with the same verified email
- **THEN** the login is rejected as an email conflict and the account keeps exactly one identity
