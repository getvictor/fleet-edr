## ADDED Requirements

### Requirement: Admin settings exposes a user-management page

The web UI SHALL provide a user-management page in the Admin settings area that lists operators with their role and account status and lets an authorized admin change a user's role and enable or disable a user. The page and its controls SHALL be gated on the operator's permissions: the page requires `user.read`, and the role and status controls require `user.manage`. An operator lacking the grant SHALL NOT be shown the page or its mutation controls.

#### Scenario: The users page lists operators and changes a role

- **GIVEN** an admin viewing the user-management settings page
- **WHEN** the page loads and the admin selects a new role for a listed user
- **THEN** the list shows each user with their role and status
- **AND** the new role is submitted to the user-management API
