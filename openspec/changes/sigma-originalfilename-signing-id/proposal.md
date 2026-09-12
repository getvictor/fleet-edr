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

A rule reading it stays `portable: standard`. The field is Sigma's own, and binding it to a platform-specific carrier is what every field here does: `Image` is a macOS path and `CommandLine` a macOS argument vector. It is deliberately not one of the exporter's `computedFields`, which names the fields this engine invents (`Subcommand`, `CommandArguments`, `EnvAssignments`) because Sigma has no notion of argument position. Nothing about `OriginalFileName` is invented.

## What does not change

The refusal path itself. Two rules stay refused, for the unrelated reason that they watch file paths this agent does not emit events for; that is #998.

## The unsigned case is the risk

An unsigned process has no signing identifier. The field must be ABSENT rather than an empty string, and the difference is not visible through `contains`: a non-empty pattern matches neither an absent field nor an empty one, so no fixture written with `contains` can tell the two apart.

It shows up where a rule asks about the field itself. `OriginalFileName: null` is Sigma's test for "this process has no such name", which is true of every unsigned binary and must match; `OriginalFileName: ''` asks for a present-but-empty identifier, which no process has and must not match. Supplying `""` inverts both answers, so an unsigned process would be reported as carrying an empty compiled name rather than none. That is the assertion the field-level test pins, because the substring tests cannot.
