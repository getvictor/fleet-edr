# Record a capture-provider recovery failure as a host health episode

Issue #778. This is the first of two changes; it moves where the signal is recorded. The operator-facing surface and the notification path follow in the second.

## The problem

`sensor_recovery_failed` reports that this product's own automatic repair of a stopped capture provider gave up. Both outcomes it can carry name our software: the repair command failing points at the host application or the configuration daemon, and the repair reporting success while the provider stays stopped points at the extension. Nothing adversarial is established, which is why #754 already removed its ATT&CK mapping. It is an operational fault, and it currently sits in the analyst's detection queue.

## What is already true, and why the alert is still there

Half of "surface it as health" is already shipped and easy to miss. `selfheal.Controller.escalate` calls `MarkSelfHealFailed`, so the owning component already reports `status: unhealthy` with reason `self_heal_failed` through the status check-in, and the host already reads unhealthy in the console.

The alert row exists for the half that does not. The agent wiring says so directly: health is level state, so once an operator fixes the host by hand it reads healthy again and nothing records that the host went uncaptured at all, let alone for how long. The alert is the durable account. The 37.8-hour providerless episode that motivates this whole area is exactly the fact that would leave no trace.

So the signal cannot simply be deleted from the alerts table. What it needs is a durable home that is not the detection queue.

## What changes

A host health EPISODE becomes a persisted thing in its own right: a record that a named component on a named host entered a fault at a point in time, what the fault was, and when it ended.

An episode carries the three facts that make this one actionable (the provider, the outcome, and how many repairs were attempted) as fields rather than as prose, and it carries a resolution time. The resolution time is the part the alert never had: an episode closes when the component reports healthy again, so the record answers "how long was this host not capturing" directly rather than leaving it to be reconstructed by hand from an archive.

The detection engine stops persisting health-kind findings as alerts. It already routes a finding by the mode an operator resolved for the rule; it now also routes by the kind the rule declares, which #775 put on the rule for exactly this sort of decision. A finding from a rule that declares itself a health signal is recorded as an episode. Every other rule is untouched.

## What does not change

- `sensor_tamper` stays a detection. It answers "did somebody switch capture off", which is a claim about a person.
- `application_control_block` stays an alert. It is a non-detection too, but a PROJECTION: the decision it renders was made on the host and belongs in the queue an analyst works.
- Alerts already raised by this rule are left where they are, readable as history. Rewriting them into episodes would invent a resolution time nobody observed, and deleting them would destroy the only record of the episodes they describe.

## The notification gap this opens, and when it closes

The outbound webhook is alert-shaped, so today this rule reaches an off-console operator only because it is an alert. That path goes away with the alert row, and this change alone leaves the signal visible in the console but silent everywhere else. The second change adds the operator surface and a health event to the webhook, and the two ship in the same release. Naming it here because a reader arriving at this change alone would otherwise read the gap as an oversight.
