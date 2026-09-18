# A contained host says when its names are not filtered

Issue #1078. Containment restricts a contained host's DNS in two layers and only one of them always holds. The content filter allows DNS to the host's own resolvers whatever else is running. The network extension's DNS proxy is what refuses every name but the server's, and it cannot while it is not running, so a host contained with the proxy disabled or stopped resolves any name those resolvers answer.

Nothing told the operator that, and the reason is upstream of containment: a provider an operator switches off is reported by OMISSION, which was chosen so it would not read as a fault forever. Omission also makes it indistinguishable from an extension too old to report anything, so no reader can tell "switched off" from "never said".

A first attempt (PR #1099) reported it from the containment status into the command result. That was closed: a completed command result is immutable, so it went stale the moment the proxy stopped afterwards, and the lifecycle flag it read cannot see a provider that wedges while still reporting itself running. Both failures under-reported, telling an operator a host was safer than it was.

## What changes

- **A deliberately disabled provider is reported as `disabled` rather than dropped.** Still not a fault, still never pages anyone, but now visible. This is the root cause: the state existed and was thrown away.
- **The agent grades it as a state.** Its own component says the provider is turned off, under a reason of its own, and it does not make the network extension unhealthy.
- **The extension remembers what was switched off.** A disabled provider never starts and so never stops, so a restarted extension has no callback telling it the provider is off and would report the host as saying nothing again. The observed state is persisted and seeded at start, and corrected the moment the provider does run.
- **The console qualifies a contained host from live health.** It says a contained host's DNS is restricted by destination only when health says the proxy is disabled, or when the server's derived condition says no DNS capture arrived while process telemetry continued. The second covers the wedged provider a lifecycle state cannot see.

This follows how the industry reports degraded enforcement: as live sensor health beside the action, not as a property of the action's result. CrowdStrike's Reduced Functionality Mode and Defender's impaired and misconfigured device health are the same shape.

Because `disabled` is a new word in a vocabulary several readers already share, every consumer that stated the old contract is corrected with it rather than left describing absence: the self-heal eligibility rule, the sensor-tamper and recovery-failed detections and the operator documentation generated from them, and the requirements that named the opt-out as absence. Absence stays supported and stays benign, since an extension predating this still reports that way.

## Out of scope

Making the DNS proxy non-optional while contained, or answering names locally in the extension so the restriction does not depend on the proxy at all. That is the structural fix for containment depending on an optional component, and it deserves its own issue.
