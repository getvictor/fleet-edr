# Network arm sees a shell that exec'd its payload in place

## Why

`suspicious_exec`'s network arm resolves its shell ancestor through the PPID chain only. A shell invoked as `zsh -c '<cmd>'` replaces its own image with the payload rather than forking it, so the payload runs at the shell's PID and nothing in the payload's ancestry is a shell. The walk steps over the closed shell generation, reaches the interactive login shell above, and rejects it on the 30-second window, so the rule reports nothing.

The exec arm already handles this shape: `evalExecArm2` walks `GetExecChain` for exactly the same reason. The network arm has no equivalent, which is issue #713.

The practical effect is that detection depended on which shell the attacker chose. Measured on macOS 26.6.1 by spawning each shell from python3 with a single redirected command: `zsh` replaces itself with the payload, while `bash` and `sh` fork it. So `python3 -> Popen(['/bin/zsh','-c','curl ...'])` was invisible while the identical `/bin/bash` form was detected. This is how the miss was reported: an operator ran the payload and saw no alert.

## What changes

- The network arm consults the connecting PID's own exec chain when the PPID walk yields no shell it can fire on, mirroring the exec arm.
- The fall-through triggers on "no usable shell" rather than "no shell". Where a shell exec'd in place the walk does not come back empty, it comes back with the WRONG shell (the stale interactive one), so a `shell == nil` gate would never reach the chain.
- The connecting process is resolved before the shell decision rather than after, because the chain walk needs that generation. This costs one indexed read on outbound flows that have no shell ancestor, against the two to four the ancestor walk already performs.

No wire, schema, or agent change. The 30-second window, the parent exclusions, and the per-batch shell dedup all continue to govern; the chain is a second place to look for the shell, not a way around the gates.

## Impact

- Affected specs: `server-detection-rules-engine`
- Affected code: `server/rules/internal/catalog/suspicious_exec.go`
- New efficacy corpus scenario `T1059.004-shell-inplace-exec-network`, which fails without the change (the rule does not fire within the 30s SLA) and passes with it.
