## ADDED Requirements

### Requirement: Host network containment in the console

The host page header SHALL show where the host's network containment stands: Containing while a containment has not been confirmed by the host, Contained once it has, Containment failed when the host reported it could not apply it, Releasing and Release failed likewise for a release, and nothing for a host that is not contained. While a containment or release is on its way the page SHALL re-read the state until the host confirms or fails it, and SHALL NOT poll otherwise. An operator holding `host.isolate` SHALL be offered Contain host on a host that is not contained and Release host on a contained one; the action SHALL ask for a reason (required, at most 1024 characters) in a confirmation that says what containment does before it is sent, and SHALL go through the reauthentication prompt when the session needs a recent authentication. An operator without `host.isolate` SHALL see the state without the action. The host list SHALL show the same badge on each host that has one.

#### Scenario: An operator contains a host from its page

- **GIVEN** an operator holding `host.isolate` on the page of a host that is not contained
- **WHEN** they choose Contain host, give a reason and confirm
- **THEN** the containment is requested with that reason, the header shows Containing, and it shows Contained once the host confirms it

#### Scenario: A contained host can be released

- **GIVEN** an operator holding `host.isolate` on the page of a contained host
- **WHEN** they choose Release host, give a reason and confirm
- **THEN** the release is requested with that reason and the header shows Releasing

#### Scenario: Without host.isolate the state is shown and the action is not

- **GIVEN** an operator without `host.isolate` on the page of a contained host
- **WHEN** the page loads
- **THEN** the header shows Contained and offers neither Contain host nor Release host

#### Scenario: The host list marks hosts under containment

- **GIVEN** a contained host, a host whose containment is on its way, and a released host
- **WHEN** the operator opens the hosts page
- **THEN** the first shows Contained, the second Containing, and the released host shows no containment badge
