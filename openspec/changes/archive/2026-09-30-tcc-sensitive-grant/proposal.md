## Why

Infostealers and remote-access tools need Full Disk Access, Accessibility, Screen Recording or Input Monitoring to work, and a user talked into granting one is the usual way they get it (MITRE T1548.006, issue #1185). The security extension now reports every TCC permission change, and the agent adds the granted app's signature; nothing raises an alert on them.

## What changes

- A new rule, `tcc_sensitive_grant` (medium), fires when Full Disk Access, Accessibility, Screen Recording, Input Monitoring or the right to post input events is granted to an app that is not an Apple platform binary, through a prompt or System Settings.
- A grant made by an MDM configuration profile, the managed way to deploy these permissions, is not reported, and neither is one to an app whose signature could not be read.
- An operator waives an app by its team, team-qualified signing identifier or path. One alert is raised per app and permission.
- The agent resolves a bundle identifier to its app through LaunchServices and reads the app's code signing, attaching both to the event.

## Not changed

A permission granted by writing the TCC database directly, which bypasses tccd, raises no TCC event and is not reported.
