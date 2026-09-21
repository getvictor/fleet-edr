# The single sign-on page saves against what it was shown

Issue #1046, the page half. The server now reports a version with the settings and refuses a save that names a superseded one (#1133), but the page sent none, so it kept overwriting whatever had been saved while it was open.

## What changes

- **The page sends the version it was shown**, and the one its own last save returned, so an operator can save twice without reloading.
- **A conflict reads as what happened.** Nothing was saved, somebody else changed the settings, and reloading is how the operator sees what changed. A raw `API error: 409 Conflict` tells them none of that, and is the shape the capability-gating work already ruled out for denials.
- **`updateSSOConfig` goes through the shared typed-mutation client**, the one the app-control and detection-config surfaces use, so the wire code reaches the page instead of being flattened into a status string.

## What this does not claim

Retrying is not offered. The point of the refusal is that the operator has not seen the change they would be overwriting, and a retry button would put it back one click away.
