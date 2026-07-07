## ADDED Requirements

### Requirement: Admins pre-provision users into a staged role through an audited API

The system SHALL expose an admin API that creates a user from an email and a bindable role before that user has ever authenticated, gated by the existing `user.invite` action. The created account SHALL hold exactly one global role binding for the chosen role, SHALL have no usable credential, and SHALL carry a distinct `provisioned` lifecycle status that distinguishes it from `active` and `disabled` accounts. The role SHALL be one of the seeded bindable roles (`analyst`, `senior_analyst`, `auditor`, `admin`); the endpoint SHALL reject `super_admin` unless the acting operator is itself a `super_admin`, and SHALL reject any unknown role. Creating a user whose email already exists SHALL fail without mutating state. Every applied creation SHALL emit a `user.provisioned` audit row recording the acting operator, the target user, and the assigned role.

#### Scenario: Admin pre-provisions a user into a senior role

- **GIVEN** an operator holding `user.invite`
- **WHEN** they create `alice@example.com` with role `senior_analyst`
- **THEN** a new user exists with status `provisioned`, no credential, and exactly one global binding for `senior_analyst`
- **AND** a `user.provisioned` audit row records the acting operator, the target user, and the role `senior_analyst`

#### Scenario: A role without the invite grant is denied

- **GIVEN** an operator holding only the `analyst` role
- **WHEN** they attempt to pre-provision a user
- **THEN** the chokepoint denies the request and no user is created

#### Scenario: Pre-provisioning rejects the super admin role

- **GIVEN** an operator whose own role is `admin`
- **WHEN** they attempt to pre-provision a user with role `super_admin`
- **THEN** the request is rejected and no user is created

#### Scenario: Pre-provisioning a duplicate email is rejected

- **GIVEN** an existing user `bob@example.com`
- **WHEN** an operator holding `user.invite` attempts to pre-provision `bob@example.com`
- **THEN** the request is rejected and the existing user is unchanged

#### Scenario: A pre-provisioned account cannot be moved off the provisioned status before first login

- **GIVEN** a pre-provisioned user that has not yet signed in
- **WHEN** an operator attempts to set that user's status to active or disabled
- **THEN** the request is rejected and the user keeps the `provisioned` status, so first-login adoption can still match

### Requirement: First SSO login adopts a pre-provisioned account into its staged role

When an OIDC sign-in presents a subject with no existing identity and an explicitly verified email (the `email_verified` claim is present and true) that matches a pre-provisioned account, the system SHALL adopt that account rather than create a new one or reject the login: it SHALL link the OIDC identity to the existing user, transition the account status from `provisioned` to `active`, and retain the pre-assigned role instead of binding the default JIT role. This adoption SHALL occur regardless of whether just-in-time provisioning is enabled, because pre-provisioning is an explicit administrative staging decision. Adoption SHALL require explicit email verification, stricter than just-in-time creation, because it binds an external subject to a pre-staged and possibly elevated role: an absent `email_verified` claim SHALL NOT adopt. The status transition SHALL be the single-winner serialization point so two concurrent sign-ins for the same staged email can never both bind: at most one SHALL adopt and the other SHALL be rejected as an email conflict. An email that already belongs to an account with any identity, or to a break-glass account, SHALL still be rejected as an email conflict.

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
