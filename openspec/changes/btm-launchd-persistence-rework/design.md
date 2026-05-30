# Design

Full rationale and the captured ground-truth live in the ADR-0008 amendment (PR #305) and
`ai/btm-attribution/experiment.md`. This change records the spec deltas that follow from those decisions.

## Discriminator: registered executable, not instigator

The BTM event (`es_event_btm_launch_item_add_t`) exposes code-signing only for the `instigator` and `app` **processes**,
never for the to-be-launched executable. For a `launchctl bootstrap` the instigator is Apple's `smd`, so it cannot
discriminate. The extension therefore evaluates the registered `executable_path` out-of-band via `SecStaticCode`
(`SecStaticCodeCreateWithPath` + `SecCodeCopySigningInformation`, `anchor apple` for the platform-binary flag) and emits
the result as `executable_code_signing`. `SecStaticCodeCheckValidity` runs with `.noNetworkAccess` so an ES callback
thread never blocks on an OCSP/CRL fetch. This also sidesteps the #187 ad-hoc-extension ESF signing redaction, since
`SecStaticCode` reads the signature from disk rather than trusting the (redacted) ESF process fields.

The rule allows (skips) an executable that is an Apple platform binary, MDM-managed, or signed by an allowlisted team ID;
everything else fires. Notarization is deliberately NOT a trust signal: it is an automated Apple scan, not an endorsement
(Apple has notarized malware), and a prototype confirmed it is not checkable network-free in-process
(`SecAssessmentTicketLookup` is not public; `SecAssessment`/Gatekeeper can hit the network, the ES-thread deadlock Gemini
flagged). Trust is the team-ID allowlist; notarization/reputation, if ever pursued, belongs server-side off the hot path.

## Process-optional alerts and subject dedup

`alerts.process_id` is FK-constrained to `processes(id)`, so a process-less alert cannot carry a real process row. The
column becomes nullable (enrichment only), and a `subject VARCHAR(255) NOT NULL` column carries the dedup identity:
`InsertAlert` defaults it to the process id string for process-backed callers (preserving prior dedup) and the firing
rule supplies it for process-less callers. A process-less alert with no subject is rejected rather than collapsing to
subject `"0"`. The unique key `uk_alerts_dedup` moves to `(source, host_id, rule_id, subject)`.

## Spec markers

The three new normative scenarios are covered by existing tests via canonical-ID markers (spectrace `--strict`): the
detection store test (`TestStore_InsertAlert_ProcessLess`) covers the process-less persist + subject-dedup scenarios,
and the Swift serializer test covers the launch-item event scenario.
