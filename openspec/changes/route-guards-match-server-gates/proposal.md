# Guard a console route with the action its data actually needs

## Why

The console's route guards and the server's gates disagree in both directions, and each direction has a symptom.

Coverage is ungated in the console: its nav entry declares no action and its route carries no permission wrapper, on the stated grounds that the entry "guarantees a match for every authenticated operator" and so gives the landing redirect something to resolve to. The server gates `GET /api/attack-coverage` on `alert.read`. An operator holding nothing therefore lands on Coverage, is the only entry they can see, and reads `Error: API error: 403 Forbidden`. That is the raw transport error the graceful-denial requirement exists to prevent, reached through the one route that was never gated.

The Rules catalogue is gated the other way. Its route requires `rule_content.read`, which the analyst and auditor roles do not hold, but the data behind it is `GET /api/rules`, which the server gates on `alert.read`. Those two roles are refused a page the server would serve them. The rule catalogue is deliberately the less restricted surface: the export route reasons explicitly that widening its gate "would take export away from those roles for the built-in ones, which they can already read on the catalog". The console does not honour that, so an analyst cannot reach the catalogue the server considers theirs.

## What changes

Each route is guarded by the action its own data needs, which is the action the server gates that data on.

Coverage, the rule catalogue, a rule's detail and a rule's monitor records all read surfaces the server gates on `alert.read`, so all four are guarded on `alert.read`. The rule editor keeps `rule_content.write`, and the built-in rules panel on the catalogue page, which reads the authoring surface, is shown only to an operator holding `rule_content.read`.

No role's grants change and no server gate changes. What changes is which operator the console lets through to which page, so that it matches what the server would already have answered.

## Impact

- Affected specs: `web-ui`
- Analysts and auditors gain the rule catalogue, a rule's detail, and its monitor records in the console. The server already served all three to them.
- An operator holding no actions at all now reaches the no-access state rather than a raw 403.
