# Operators edit the watched file paths in the console

Issue #998 (ADR-0008 step 4). The sensor change taught the extension to watch paths the server pushes, the server change gave the set an API and a push, and the converge change brings hosts that missed a push up to date. Changing the set still took a hand-written API call. This change adds the editor to Detection tuning, next to the exclusions and rule modes the same operators already tune.

## What changes

- **A Watched file paths section in Detection tuning.** It lists the stored set, says which paths every host always watches (from the API's `built_in`), and shows how many of the allowed paths are used and when and by whom the set was last saved.
- **Editing a draft of the whole set.** An operator with `detection_config.write` adds a path as a single file or everything under a directory, removes entries, and can discard the draft. Saving asks for a reason, sends the whole set with `PUT /api/v1/detection-config/watched-paths`, and reports the version saved and how many enrolled hosts the set was queued for, including that the rest receive it within minutes when some could not be queued, and a push skipped because hosts could not be listed.
- **The server stays the one validator.** The editor refuses only what it can see without restating server rules: an empty path, an entry already in the draft, and a draft at the size bound the API reports. Anything else the server refuses is shown as the server wrote it, with the draft kept so the operator can fix it.
- **Readers see, and do not edit.** Without `detection_config.write` the section shows the set with no editing controls.
- **Docs.** `docs/operations.md` describes watching more file paths.

## Out of scope

- Host-reported state (which set each host applied). The agent reports the version in the command result; surfacing it per host is a later change.
- Scoping the set to host groups.
