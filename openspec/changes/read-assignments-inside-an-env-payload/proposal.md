# Read assignments inside an env command-line payload

## Why

`env -S` carries a whole command line as its operand, which env re-splits and processes as its own argument list. Measured against `env(1)` on macOS: `env -S "DYLD_INSERT_LIBRARIES=/tmp/x prog"` applies the assignment and it reaches the child's environment. The field reported nothing, so `dyld_insert` did not fire, and that is a live bypass an attacker can pick deliberately.

Reporting nothing was the SAFE direction rather than a correct one, which is why #860 pinned it as a known gap instead of guessing: the alternative it rejected was reporting the tokens after the payload, and those belong to the command. Measured: `env -S "A=1 /bin/echo" B=2` prints `B=2`, so the trailing token is echo's argument.

env's rarity in telemetry (#791 measured one env invocation across 670,185 execs) argues for closing this rather than against it. An attacker picks the form because it evades, so rarity of the benign case says nothing about the malicious one, and it also means a false positive here costs almost nothing.

## What changes

- A `-S` payload is split and its leading assignment run is read with the same boundaries as any other env argument list, so an embedded `-i` is skipped and a nested `-S` reports nothing, with no special cases.
- Tokens after the payload are still never assignments. The outer run ends exactly as before.
- A payload containing `'`, `"`, `\` or `$` reports nothing. Those are constructs env's split performs (quotes group and are stripped, a backslash escapes the next character, `${VAR}` substitutes from env's own environment) and emulating a subset of them would report an assignment env did not apply. A fabricated injection finding is worse than the miss it replaces.

## Impact

- Affected specs: `server-detection-rules-engine`
- Affected code: `server/rules/internal/sigmabind/argv.go`
- No wire, schema or migration change. `dyld_insert` fires on a shape it previously missed.
