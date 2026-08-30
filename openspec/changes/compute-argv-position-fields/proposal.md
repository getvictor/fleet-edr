# Compute argument position as matchable fields

## Why

#761 assumes the Sigma-expressible detections convert to `portable: standard`. They do not. All three rules reachable today decide on the POSITION of a token in argv, and Sigma has no notion of position: `CommandLine` is one string, and by the time a rule sees it the argument boundaries are gone.

Measured against the fixtures the Go rule is already pinned to, the naive conversion of `credential_keychain_dump` (`Image|endswith: '/security'` plus `CommandLine|contains: 'dump-keychain'`) fires on `security help dump-keychain`, which the Go rule deliberately does not. There is already a committed fixture for it, `negative_help_mentions_subcommand`. So the issue's own acceptance criterion, that existing per-rule tests pass unchanged, fails for the conversion the issue proposes.

## What changes

Three computed fields on exec events, so the positional facts can be matched as ordinary fields. This is the approach epic #756 already settled on: "where a native predicate is tempting, compute it at ingest and match it as a field, the way Sysmon precomputes `Hashes` and `OriginalFileName`."

| Field | Is | Serves |
|---|---|---|
| `Subcommand` | the first non-flag token after argv[0] | `credential_keychain_dump`, `persistence_launchagent` |
| `CommandArguments` | the non-flag, non-empty operands after the subcommand, list-valued | `persistence_launchagent` |
| `EnvAssignments` | the leading `KEY=VALUE` window, list-valued | `dyld_insert` |

None of the three names is used by any rule in the 3,141-rule upstream corpus, so nothing imported can collide with them.

`EnvAssignments` is the clearest illustration of why position has to be recovered: `DYLD_INSERT_LIBRARIES=x /bin/true` and `/bin/true DYLD_INSERT_LIBRARIES=x` produce an identical `CommandLine`, and only the first is an injection.

## Consequence for the issue's expectations

The three rules become `portable: mapped`, not `standard`: still valid Sigma, but needing a field only we supply. That is an accurate label rather than a downgrade. A `standard` rule that silently over-matches would be worse than a `mapped` one that is correct, and saying so honestly is what `x-engine.portable` is for.

## One deliberate behaviour change

`Subcommand` treats an empty token as the subcommand rather than skipping it, so `launchctl "" load x.plist` no longer fires. The Go matcher skips it, but only because it uses `""` as its not-found sentinel and cannot record an empty verb; that is an artifact rather than a decision. `launchctl` would reject the empty verb and load nothing, so firing on it is a false positive, and the correction only ever removes findings. The shape does not occur in real telemetry: of 59 empty-argument execs on a dev host, every one was `sudo -p ""`, and none was launchctl.

## Impact

No behaviour change yet: nothing reads the new fields until #761's conversion. What lands here is the equivalence evidence that conversion depends on.
