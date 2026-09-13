## ADDED Requirements

### Requirement: The account menu names the session's role and sign-in method

The account menu dropdown SHALL name the roles the session carries, under the signed-in email, using the same label for a role that every other surface uses, and SHALL say when the session carries none. It SHALL name how the session was signed in: `SSO` for a session minted by any OIDC provider, and `break-glass` for a break-glass session. Neither SHALL appear on the always-visible trigger, which continues to conceal the signed-in identity until the menu is opened.

#### Scenario: An SSO operator sees their role and sign-in method

- **GIVEN** an operator signed in through SSO with the senior analyst and auditor roles
- **WHEN** they open the account menu
- **THEN** it names both roles and says the session was signed in with SSO
- **AND** before it is opened, neither is shown

#### Scenario: A break-glass operator sees their role and sign-in method

- **GIVEN** an operator signed in through break-glass with the super admin role
- **WHEN** they open the account menu
- **THEN** it names the super admin role and says the session was signed in with break-glass
