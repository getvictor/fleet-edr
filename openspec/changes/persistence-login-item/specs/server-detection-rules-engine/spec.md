## ADDED Requirements

### Requirement: Login item persistence judged on the helper

The `persistence_login_item` rule SHALL fire on a `btm_launch_item_add` event with `item_type=login_item` that is not MDM-managed and whose `executable_code_signing`, the helper app bundle's code signature, is present and not an Apple platform binary. It SHALL NOT fire on a registration whose helper's signature is absent, or on any other item type. The finding SHALL name the helper by its bundle's filesystem path, carry no process, and deduplicate per helper. An exclusion for the rule SHALL suppress it by the helper's team, by its signing identifier qualified by that team, or by a path glob on the helper bundle's filesystem path.

#### Scenario: An untrusted login item fires

- **GIVEN** a login-item registration that is not MDM-managed, whose helper is ad-hoc signed
- **WHEN** detection evaluates the event
- **THEN** `persistence_login_item` raises a medium-severity finding naming the helper bundle's path, with no process

#### Scenario: An Apple or managed login item does not fire

- **GIVEN** a login-item registration whose helper is an Apple platform binary, and another that MDM manages
- **WHEN** detection evaluates the events
- **THEN** no finding is raised

#### Scenario: A login item with no signature is skipped

- **GIVEN** a login-item registration that carries no helper signature, as an agent that does not sign login items sends it
- **WHEN** detection evaluates the event
- **THEN** no finding is raised

#### Scenario: A vendor login item is waived by its signer or path

- **GIVEN** an exclusion for `persistence_login_item` naming the helper's team, its team-qualified signing identifier, or a path glob matching its bundle
- **WHEN** detection evaluates the helper's registration
- **THEN** no finding is raised
- **AND** an ad-hoc helper claiming the vendor's signing identifier still fires, as does the helper when the team is excluded only for another rule
