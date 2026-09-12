# Supply OriginalFileName from the code-signing identifier

## Why

One of the three SigmaHQ macOS rules this sensor refuses is refused for a single missing field:

```
proc_creation_macos_remote_access_tools_renamed_meshagent_execution.yml
  -> refused: OriginalFileName is a field this sensor does not collect
```

The refusal is the contract working: a rule reading a field we do not supply is refused by name rather than imported to match nothing forever. But the capability is not missing, only unmapped.

`OriginalFileName` is a Windows PE version-info concept, the name a binary was compiled as, which does not change when it is renamed on disk. That is the whole point of the rule, which catches a remote-access tool renamed to hide it.

macOS has an equivalent and we already collect it. The code-signing identifier is embedded in the signature and survives a rename; changing it invalidates the signature. Every exec event carries `code_signing.signing_id`, and the process rows carry it too.

## What changes

`OriginalFileName` becomes a supplied Sigma field for `process_creation`, sourced from the exec event's code-signing identifier.

A rule reading it is `portable: mapped` rather than `standard`, like `EnvAssignments`: valid Sigma, reading a field this engine computes rather than one from Sigma's own taxonomy.

## What does not change

The refusal path itself. Two rules stay refused, for the unrelated reason that they watch file paths this agent does not emit events for; that is #998.

## The unsigned case is the risk

An unsigned process has no signing identifier. The field must be ABSENT rather than an empty string, because a rule matching `OriginalFileName|contains` against an empty value would match every unsigned binary on the host: precisely the population an attacker's renamed tool sits in.
