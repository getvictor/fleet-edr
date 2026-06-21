## ADDED Requirements

### Requirement: User management is gated by a dedicated admin action

The system SHALL register the action `user.manage` in the authorization action enumeration, mirrored in the policy bundle so the build-time parity check holds. `user.manage` SHALL be granted to the seeded `admin` role; `super_admin` covers it via its wildcard. The user-management mutation endpoints SHALL funnel through the chokepoint on `user.manage`, and the user-listing endpoint SHALL funnel through the chokepoint on the existing `user.read` action, like every other privileged action.

#### Scenario: Admin holds the user-management action

- **GIVEN** an operator with the seeded `admin` role
- **WHEN** the chokepoint evaluates a `user.manage` request
- **THEN** the decision is allow

#### Scenario: A role without the grant is denied

- **GIVEN** an operator with only the `analyst` role
- **WHEN** the chokepoint evaluates a `user.manage` request
- **THEN** the decision is deny with the no-matching-rule reason

### Requirement: Operators manage users and their roles through an audited API

The system SHALL expose an admin API that lists users with their effective role and account status, sets a user's role, and enables or disables a user. Setting a role SHALL replace the user's global role bindings transactionally so a user holds exactly one global role afterward. Every applied mutation SHALL emit an audit row recording the acting operator and the target user: a role change emits `authz.role_binding.update` (or `authz.role_binding.create` when the user had no prior global binding, or `authz.role_binding.delete` when access is cleared), and a status change emits `user.disabled` or `user.enabled`. A mutation that changes nothing SHALL succeed without emitting an audit row.

#### Scenario: Listing users returns each user with role and status

- **GIVEN** an authenticated operator holding `user.read`
- **WHEN** they call the user-list endpoint
- **THEN** the response carries each user with their effective role and account status

#### Scenario: Setting a role replaces the global binding and is audited

- **GIVEN** a user bound to `analyst` and an operator holding `user.manage`
- **WHEN** the operator sets that user's role to `senior_analyst`
- **THEN** the user holds exactly one global binding, for `senior_analyst`
- **AND** an `authz.role_binding.update` audit row records the acting operator, the target user, and the previous and new roles

#### Scenario: Disabling a user is audited and blocks access

- **GIVEN** an active user and an operator holding `user.manage`
- **WHEN** the operator disables that user
- **THEN** the user's account status becomes disabled
- **AND** a `user.disabled` audit row records the acting operator and the target user

### Requirement: User-management guardrails prevent lockout and privilege escalation

The system SHALL reject a mutation that would leave the deployment with no active admin: demoting or disabling the last active user holding `admin` or `super_admin` SHALL fail. An operator SHALL NOT change their own role or disable themselves through this surface. A user with the break-glass flag SHALL NOT be modified through this surface. Only a `super_admin` actor MAY grant the `super_admin` role, and an `admin` actor SHALL NOT modify a user who currently holds `super_admin`. Each rejected mutation SHALL leave all persisted state unchanged.

#### Scenario: The last admin cannot be demoted or disabled

- **GIVEN** exactly one active user holds an admin-tier role
- **WHEN** an operator attempts to demote or disable that user
- **THEN** the request is rejected and the user keeps the admin-tier role and active status

#### Scenario: An operator cannot change their own role

- **GIVEN** an operator holding `user.manage`
- **WHEN** they attempt to change their own role or disable themselves
- **THEN** the request is rejected and their role and status are unchanged

#### Scenario: Break-glass users cannot be modified

- **GIVEN** a user with the break-glass flag set
- **WHEN** an operator attempts to change that user's role or status
- **THEN** the request is rejected and the break-glass user is unchanged

#### Scenario: Only a super admin may grant the super admin role

- **GIVEN** an operator whose own role is `admin`
- **WHEN** they attempt to set another user's role to `super_admin`
- **THEN** the request is rejected and the target user's role is unchanged
