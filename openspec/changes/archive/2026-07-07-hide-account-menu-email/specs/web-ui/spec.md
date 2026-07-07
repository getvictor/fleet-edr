## ADDED Requirements

### Requirement: Account menu conceals the signed-in identity until opened

The account menu in the top navigation SHALL NOT render the signed-in user's email in the always-visible bar. The collapsed trigger SHALL show only a non-identifying avatar (the email's first initial) and, for a break-glass session, the auth-method badge. The signed-in email SHALL be revealed only inside the account-menu dropdown, which opens on an explicit operator action. The trigger SHALL carry an accessible name so assistive technology can identify it even though it has no visible text label. This prevents passive disclosure of the operator's account to anyone viewing the screen, while keeping the identity one click away for a deliberate "who am I signed in as" check.

#### Scenario: The signed-in email is hidden until the account menu is opened

- **GIVEN** an operator is signed in and viewing any application page
- **WHEN** the account menu is collapsed (its default state)
- **THEN** the signed-in email is not present in the rendered page
- **AND** when the operator opens the account menu, the dropdown reveals the signed-in email
