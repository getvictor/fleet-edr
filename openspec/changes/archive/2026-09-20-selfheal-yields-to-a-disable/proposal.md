# Self-heal yields to an operator who disables a provider

Issue #1104. Found while reviewing #1103, and it predates that change.

The eligibility filter already stops a disabled provider from STARTING a remediation: `Remediable` matches `stopped` positively, and neither `disabled` nor absence is that. The gap is the repair already running. `Observe` launches it on a goroutine and nothing stops it, so an operator who disables a provider while an enable is in flight has it turned back on underneath them, which is the outcome "Remediation never overrides a deliberate operator decision" exists to prevent.

## What changes

- **An enable in flight is stopped when the provider is reported `disabled`.** The controller keeps the cancel for the attempt it planned, and cancels it on learning of the decision. The darwin remediator runs the host-app subcommand through `exec.CommandContext`, so cancelling it ends the subprocess rather than merely abandoning its result.

  How much that buys is worth stating plainly, because it is less than it sounds. Measured on edr-dev, `edr enable-dns-proxy` returns in about 13 milliseconds from a genuinely disabled state (three runs: 13.4, 13.6, 12.6 ms; `enable-filter` 10.2 ms). The subprocess has therefore almost always exited before any liveness report could arrive to cancel it, so in ordinary operation the cancellation interrupts nothing. It earns its place in the pathological case the remediator's own 60-second timeout exists for, a wedged configuration daemon where the enable does hang, and it costs nothing in the common one. The substance of this change is the state half below.
- **Only the affirmative state does this.** Absence is left alone. It is also how a host reports a provider before anything has started, how an extension predating `disabled` reports a disable, and what a report that did not decode leaves behind. The existing code is careful about this for clearing state and the same care applies here: abandoning a repair nobody asked to stop is the opposite failure.
- **The episode is dropped with the attempt.** Previously state was cleared only on an affirmative `running` report, so a provider that stopped, was disabled, and later stopped again met the first episode's grace deadline, attempt count and escalation verdict. It now starts from a fresh grace window and a full budget, which is what a new fault is.
- **A finished attempt is matched to its own episode, not to the provider name.** A provider can come back and stop again while an enable is still running. The returning attempt now compares the episode it was launched for by identity and discards itself if that episode is over. Without this the attempt lands on whichever episode currently holds the name: it spends a budget that stop never used, and on the last attempt of a budget it escalates, telling the operator recovery had been given up on a fault nothing had been tried for.

## What this does not claim

It does not make the race unwinnable, and given the 13 ms measurement above it usually will not even be close. An enable that completed before the disable reached the agent has already written the preference, and the agent learns of the decision only from the extension's next liveness report. What is guaranteed is that the agent stops as soon as it is told and does not resume, rather than finishing a repair it now knows is unwanted. Closing the window entirely would mean the extension refusing an enable for a provider its own disabled-provider store says is off, which is a different change in a different component.

## Out of scope

- Enforcing the operator's decision at the point of application, in the extension.
- The duplicated provider-state vocabulary between `agent/selfheal` and `agent/health`, which this adds a third constant to. Both mirror the extension's wire values deliberately; consolidating them is its own change.
