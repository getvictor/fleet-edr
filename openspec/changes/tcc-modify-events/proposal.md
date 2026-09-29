## Why

Infostealers and remote-access tools need TCC permissions (Full Disk Access, Accessibility, Screen Recording, Input Monitoring) to do their work, and getting one granted is an early, high-signal step (MITRE T1548.006, issue #1185). Nothing on the host reports a permission change: exec events show `tccutil`, but not a grant made through a prompt, System Settings or tccd itself.

## What changes

- The security extension's primary client subscribes to `NOTIFY_TCC_MODIFY` and emits a `tcc_modify` event for every permission record tccd creates, modifies or deletes: the service, the app it is about and how that app is named, the resulting right, the reason (a prompt answered, a switch changed, an MDM profile), and the instigating process's pid. The instigating process's code signing, and the responsible process's pid and code signing, are included when macOS reports them.
- The SDK's enums are sent as names, with `unknown` for a value this build does not know.

## Not changed

No rule raises an alert on these events yet; that follows as its own change, with the granted app's code signing.
