## ADDED Requirements

### Requirement: The account menu names the session's role and sign-in method

The account menu dropdown SHALL name the roles the session carries, under the signed-in email, using the same label for a role that every other surface uses, and SHALL say when the session carries none. It SHALL name how the session was signed in: `SSO` for a session minted by any OIDC provider, and `break-glass` for a break-glass session. Neither SHALL appear on the always-visible trigger, which continues to conceal the signed-in identity until the menu is opened. When the session probe does not report the roles (a server that predates the field), the menu SHALL name no role rather than say the session carries none. When a denied request refetches the session, the menu SHALL name the roles that refetch returns.

#### Scenario: An SSO operator sees their role and sign-in method

- **GIVEN** an operator signed in through SSO with the senior analyst and auditor roles
- **WHEN** they open the account menu
- **THEN** it names both roles and says the session was signed in with SSO
- **AND** before it is opened, neither is shown

#### Scenario: A break-glass operator sees their role and sign-in method

- **GIVEN** an operator signed in through break-glass with the super admin role
- **WHEN** they open the account menu
- **THEN** it names the super admin role and says the session was signed in with break-glass

#### Scenario: A session whose roles are not reported names no role

- **GIVEN** a session probe that carries no roles field
- **WHEN** the operator opens the account menu
- **THEN** it names no role, and does not say the session carries none

#### Scenario: The named role follows a refetched session

- **GIVEN** an operator whose account menu names the senior analyst role
- **WHEN** a denied request refetches the session and the refetch reports the analyst role
- **THEN** the account menu names the analyst role
