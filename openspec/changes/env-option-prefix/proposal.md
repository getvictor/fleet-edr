# An option ahead of an env assignment no longer hides it

Fixes #792.

## The defect

`envAssignments` collected the run of leading `KEY=VALUE` tokens and stopped at the first token without `=`. For an `env` invocation that put an option ahead of the assignment, the option was that token:

```
env -i DYLD_INSERT_LIBRARIES=/tmp/evil.dylib /bin/true
```

`-i` contains no `=`, the scan ended, and the assignment was never examined. The same held for `-u NAME`, `-P path`, `-S string`, and anything after `--`.

That is a real injection shape reported as carrying no assignments, so `dyld_insert` did not fire on it.

## Fix

Parse env's option prefix before collecting the assignment run: skip options, consume the operand of the options that take one, stop at `--`, then collect the leading assignments as before.

The option set is `-u`, `-P`, `-S` and `-C` from `env(1)` on macOS, and getting it wrong in either direction is a detection error rather than a cosmetic one. Treating an operand as an assignment would let `env -u DYLD_INSERT_LIBRARIES prog` read as an injection when it is the opposite, an unset. Missing one ends the scan early and hides the assignment behind it, which is the bug being fixed.

Clustering follows BSD env: the operand belongs to the LAST letter, so `-iu NAME` consumes NAME while `-uNAME` carries it attached and consumes nothing. A lone `-` is the historic synonym for `-i` and takes no operand.

One fix covers both consumers. The Sigma conversion in #761 removed the separate Go matcher, so `dyld_insert` now matches through this field and renders its finding from it.

## Weighed against #791

#791 measured that the OTHER branch of this field, an assignment in `argv[0]`, cannot fire in production: ESF serialises only `es_exec_arg`, so a shell's environment never reaches argv, and `argv[0]` was an assignment in 0 of 670,185 real exec events. The `env` branch fired once in the same sample.

So this fix matters more than the raw counts suggest: the `env` branch is the only one of the two that can fire at all, and an option prefix is exactly what an attacker writing `env -i` would produce. If the exec environment is ever captured, the injection is visible there regardless and this parsing becomes much less load-bearing, which is #791's point rather than this one's.
