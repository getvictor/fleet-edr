# Tasks

- [x] Gate `TargetFilename` on write access AND a content-changing flag in `sigmabind`, with the measurement behind it recorded next to the gate.
- [x] Remove `WriteIntent` and `MutatingOpen` from the taxonomy, the event struct, and the exporter's computed-field set.
- [x] Reduce `sudoers_tamper`'s detection to its path test and regenerate the pack; it becomes `portable: standard`.
- [x] Update the rule's operator documentation: what it detects, and the legacy-agent trade in its limitations.
- [x] Rework the tests that encoded the retired behaviour, keeping the equivalence property with one asserted carve-out rather than dropping it.
- [x] Re-point the named-suppression scenario at the engine capability it describes, which the imported corpus still uses.
