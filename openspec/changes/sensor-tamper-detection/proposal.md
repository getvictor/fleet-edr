# Detect tampering with the EDR's own sensor (T1562.001)

## Why

Switching off the EDR's capture is invisible to the EDR. Measured on edr-dev: an admin disables the content filter, the extension reports the provider stopped, the agent repairs it, and the host is capturing again 36 seconds later with health back at `healthy / activated`. Nothing reaches an analyst. Agent health is level state, so the moment the repair lands there is no record that anything happened, and the self-heal (issue #682) made that window shorter rather than the evidence better.

The gap is wider than that one regression. The catalog detects tampering with the HOST's controls (`sudoers_tamper`, T1548.003) but nothing watches our own components, and the efficacy corpus carries no T1562 scenario at all. Impair Defenses is uncovered, which is a conspicuous hole for a product whose entire value depends on its sensor still being on.

Issue #685 already ships the producer half: capture-provider transitions are durable events that outlive the condition they describe. This change is the consumer.

## What changes

- **A `sensor_tamper` rule**, mapped to T1562.001, fires when a capture provider stops and capture does not resume within a short window.
- **The upgrade cutover is separated from tampering by recovery latency, not by the platform's stop reason.** This is the design decision the whole change turns on, and it was settled by measurement rather than argument. See below.
- **A correlation read on the event archive**, `EventsByTypeForHost`, so a rule can ask what a host's own event stream did next. It is bounded to the archive's sorting-key prefix (host, type, event time), which is what makes a per-stop lookup cheap.
- **Corpus coverage on both sides**: a T1562.001 attack scenario that must alert, and an upgrade-cutover noise scenario that must not.

## The discriminator, and why the obvious one is wrong

The obvious design reads the platform's stop reason: `userInitiated` means somebody switched capture off, the lifecycle reasons mean an upgrade replaced it. That design is wrong. A routine system-extension cutover on a live host produced `content_filter stopped (reason 1)`, reason 1 being `userInitiated`, byte for byte what a deliberate disable produces. A rule keyed on the reason would alert on every host on every upgrade. An alert that fires fleet-wide during routine maintenance is one operators mute, and a muted tamper alert is worse than no tamper alert, because it is also a false assurance.

What separates the two is what happens next. Recorded event timestamps from the same host:

| pair                             | gap        |
| -------------------------------- | ---------- |
| tamper, repaired by the self-heal | **37.9 s** |
| tamper, repaired by the self-heal | **32.2 s** |
| upgrade cutover                   | **1.1 s**  |

A cutover's replacement provider is running about a second later because the extension is replacing itself; a tamper's repair has to wait out the agent's grace window first. The rule fires on a stop unless capture resumes within 5 seconds, which sits an order of magnitude from both populations. The threshold is not delicately tuned, and it is deliberately not derived from the self-heal's timing, so changing the repair does not silently retune the detection.

The cheaper version of this was ruled out by the same measurement: the agent uploads every second, so a 1.1s gap straddles batches too often for "suppress when the recovery is in the same batch" to hold.

## What this deliberately does not do

The alert reports the stop, not the repair. Issue #684 asks for the outcome (healed, still stopped, or automatic recovery gave up) to be part of it. None of that is known when the stop has to be reported, and waiting for it would mean either holding batches for the length of a full self-heal or suppressing the case that matters most, a provider that never comes back. The repair is carried by the following transition records on the host's timeline. If the outcome is wanted ON the alert, the honest way to get it is for the agent to report its remediation result as its own event, which is a separate change.
