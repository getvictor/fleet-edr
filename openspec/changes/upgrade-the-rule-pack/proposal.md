# Install this build's rule pack over the stored one

## Why

A deployment seeds its rule content once, on its first boot, and the seed is deliberately guarded on the corpus being EMPTY: a seed that ran on every boot would overwrite an operator's own rules on the next restart.

That guard has a consequence nothing currently addresses. Once a deployment has seeded, it keeps that generation of shipped detections forever. An operator who upgrades the product to get new detections does not get them, and nothing anywhere says so. That is a security regression rather than an inconvenience, because the operator has every reason to believe the upgrade delivered what it advertised.

## What changes

Installing the pack in the build becomes its own operation, separate from seeding, with a narrower blast radius: it replaces the SHIPPED half of the corpus and nothing else.

- An operator's own rules survive, including one written over a shipped rule's path. Taking that path back would discard the rule they wrote and revert its credit to a project that did not write it.
- Their tuning survives without anything here helping, because per-rule mode, severity overrides and exclusions live in `detection_rule_settings` keyed by rule id rather than in these files. That separation is what makes upgrading safe at all, so it is asserted rather than assumed.
- Installing is idempotent, and the comparison that makes it so is not the obvious one. Comparing the build's pack against the recorded digest looks equivalent and is not: the recorded digest describes the shipped content actually held, so on a deployment that has overridden one shipped rule it can never equal the build's own pack digest. Triggering on that comparison would reinstall on every boot, bump the corpus version each time, and make every replica reload content that did not change.

## Impact

- `rulecontent`: a new store operation and the bootstrap surface that drives it, called once at startup after the seed.
- No migration. The columns this needs were added when provenance was recorded.
- Rollback to the previous pack, and the installed-versus-available diff, are the remainder of issue #768 and follow separately.
