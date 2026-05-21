# ESF event-envelope corpus

Wire-format goldens for the `EventEnvelope<P>` JSON the system extension's `EventSerializer`
emits in production. `CorpusReplayTests`
(`../EDRExtensionLogicTests/CorpusReplayTests.swift`) walks every `*.json` here, decodes
via the matching typed envelope, re-encodes via the production `.sortedKeys` `JSONEncoder`,
and asserts the bytes round-trip byte-stable.

What this catches:

- A rename of a `CodingKey` (`pid` → `process_id`) fails decode loudly.
- A change to `JSONEncoder.outputFormatting` produces unsorted bytes; the re-encode mismatch fails loudly.
- A flip in an optional field's encode-when policy (e.g. start emitting `snapshot=false`) shifts the bytes;
  the re-encode mismatch fails loudly.

What this deliberately does not catch:

- Adding a new optional field is backwards-compatible by design (decoder defaults absent
  field to `nil`, encoder omits `nil`, bytes unchanged). To exercise the new field, update
  the seeder in `CorpusReplayTests.swift` and run the regenerate flow below.

## Directory layout

    corpus/
      <macOS-version>/
        <scenario>/
          <event-type>.json

One directory per macOS major version because ESF surfaces new fields per release; the
harness walks every version on every run. The M8 starter set covers `macOS-26/baseline/`.

## Regenerating

When the wire format intentionally changes (a new field, a renamed key, an encoder option flip),
regenerate the goldens by re-running the seeders that live in `CorpusReplayTests.swift`:

    EDR_CORPUS_REGENERATE=1 swift test \
      --package-path extension/edr \
      --filter CorpusReplayTests

This wipes only the `baseline/` directory and rewrites it from the in-source seeders; any
sibling scenario dir holding real VM captures is preserved. After regenerating, review
`git diff extension/edr/Tests/corpus/` to confirm the change matches the source-of-truth
edit, then commit both in the same PR.

## Adding a real captured corpus

The M8 starter set is hand-seeded with sentinel `host_id` (`AAAAAAAA-0000-0000-0000-000000000000`)
and `timestamp_ns` (`1700000000000000000`, 2023-11-14 00:00:00 UTC), sufficient for wire-shape
regression coverage but not for documenting realistic payload shapes per attack scenario.

A follow-up captures real ESF emissions on the SIP-enabled `edr-qa` VM
(`192.168.64.7`, see `~/.claude/projects/-Users-victor-work-edr/memory/vm_layout.md`)
and commits those under scenario-named subdirectories such as
`macOS-26/attack-curl-bash-pipe/exec.json`. The harness needs no change to pick them up;
the directory walk in `assertEveryGoldenRoundTrips(rootedAt:)` skips only the baseline
directory (the seed-driven loop covers that one), and exercises every other `.json`
encountered under `corpus/`.
