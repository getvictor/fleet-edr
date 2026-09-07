# Make a bad rule pack recoverable

## Why

Installing the pack a build carries is one-way. Once the newer shipped content is in, the generation it replaced is gone, so an operator who finds a rule in it noisy, wrong, or expensive has nothing to go back to short of restoring a database backup. That is a poor answer for content that changes on its own cadence and lands automatically on upgrade.

## What changes

The generation an upgrade replaces is retained, and can be restored.

- **One generation, not a history.** The ask is to roll back to the previous version. A deeper history needs a retention policy, a way to name a generation, and a way to choose between them, none of which anyone has asked for.
- **A rollback survives a restart**, and this is the part that makes it real rather than theatre. Installing decides by comparing what this build's pack would store against what is stored; after a rollback those differ by construction, so without a record of the refusal the next start would reinstall exactly what the operator rejected, and every start after that.
- **Declining is about one pack, not about upgrades in general.** A boolean would leave an operator who rolled back once needing to remember to switch upgrades back on, and forgetting is silent: a fleet sits on old detections with nothing saying why. The next release ships a different pack and installs normally.
- **The operator's own rules are untouched**, as they are by an upgrade. Rolling back a PACK restores the shipped generation; it is not an undo of edits they made.

It also becomes possible to ask what a deployment is running: which shipped generation is installed, which the build carries, and which RULES differ between them.

## Impact

- `rulecontent`: one migration retaining a generation and three digests on the meta row, plus the store and bootstrap operations.
- No change to what a deployment runs until an operator rolls back.
- The operator HTTP surface for reading the status and triggering a rollback follows separately, and is what closes #768.
