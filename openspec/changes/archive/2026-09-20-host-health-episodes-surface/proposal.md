# Show recorded sensor faults on the host page

Issue #778, third of three changes. The first recorded a capture-provider recovery failure as a host health episode instead of an alert; the second delivered it to webhook destinations. This one makes the record visible in the console.

## What changes

The host detail read the host page already makes gains the host's recorded sensor faults, and the host header's Details popover lists them beneath the component conditions: each with the part at fault, why its repair gave up, and for an open fault when it began or for a resolved one how long it lasted. How long a host went uncaptured is the number the record exists to provide, and until now it had nowhere to be read.

## A recorded fault does not change the host's health status

The overall status answers whether the host is healthy now. While a fault is live, the component that reports it is already unhealthy, so the status already says so and a fault would add nothing. Raising the status for an open fault would also be wrong later: a fault recorded by an agent too old to name its component can never close, so a host that had long since recovered would read as permanently broken. The status is now; the faults are the record. The host list is therefore unchanged.

## Two gaps the first change left, closed here

- The integration stack, which the efficacy harness runs, never wired the fault recorder, unlike the server's own startup. The engine deliberately drops a health signal when no recorder is wired rather than falling back to an alert, so every cross-context test of this path saw nothing and could not tell that from the rule not firing.
- The efficacy scenario for this rule stopped asserting it when it stopped raising an alert, because the harness only knew how to look for alerts. Its `expect` field had been parsed and ignored for every scenario. It now selects what to look for, and a scenario expecting a health episode also fails if an alert was raised too.
