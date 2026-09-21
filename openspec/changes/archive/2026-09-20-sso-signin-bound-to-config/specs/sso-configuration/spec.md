## ADDED Requirements

### Requirement: A sign-in is judged under one configuration

A single sign-in SHALL be judged entirely under the stored configuration that verified its token. The connection settings that verify a token and the sign-in policy that judges its claims are one configuration, and they SHALL be read together: read separately, an administrator's save between the two leaves a sign-in verified under one configuration and judged under the next.

The sign-in policy is the just-in-time toggle, the default role, and the group mapping. A token from the provider being replaced being judged against a mapping written for its replacement is the sharpest form of this, because the result is the operator's role.

A configuration saved while a sign-in is in flight SHALL apply from the next sign-in. It SHALL NOT cause the sign-in in flight to be refused: the operator did nothing wrong, and a refusal is indistinguishable to them from the provider being down.

#### Scenario: A save during the exchange does not change this sign-in

- **GIVEN** an operator whose group is mapped to a role by the stored configuration
- **WHEN** they sign in, and an administrator saves a configuration without that mapping while the token exchange is in flight
- **THEN** the sign-in completes
- **AND** the operator holds the role the mapping gave them, under the configuration that verified their token
