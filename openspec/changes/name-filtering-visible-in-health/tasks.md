# Tasks

- [x] Report an operator-disabled provider as `disabled` instead of dropping it, keeping lifecycle stops as omission and every other reason as a fault.
- [x] Grade `disabled` as a state: its own component reason and message, and no effect on the parent.
- [x] Read the host's live health once in the header and give it to both the details popover and the containment control.
- [x] Qualify a contained host whose health says the proxy is disabled, or whose derived condition says no DNS capture arrived.
- [x] Make the explanation reachable by keyboard rather than on hover.
- [x] Cover the three stop outcomes, the disabled grading, the two health conditions, and what must NOT be shown.
- [x] Remember across an extension restart which providers were switched off, so a rebooted host does not report the provider absent again.
- [x] Sweep every consumer that stated the old contract: the sensor-tamper and recovery-failed rules, their generated operator documentation, the self-heal eligibility rule, and the requirements naming the opt-out as absence.
