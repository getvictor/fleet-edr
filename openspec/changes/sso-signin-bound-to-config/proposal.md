# A sign-in is judged under the configuration that verified it

Issue #1044. The OIDC callback built its provider client from the stored configuration, exchanged the code and verified the ID token, and then the provisioner read the configuration again for the sign-in policy: JIT on or off, the default role and, since #1042, the groups claim and group mappings. An admin saving during that exchange meant the token was verified under one configuration and its claims judged under the next.

Before #1042 the exposure was the JIT toggle and the default role. With group mapping it is a role: a token from the provider being replaced could be evaluated against a mapping written for its replacement. Reaching it needs an account at the outgoing provider whose sign-in completes inside the token exchange round trip of the admin's save.

## What changes

- **The sign-in policy travels with the provider configuration.** The resolver's read carries it, `Current` returns it with the client, and the callback passes it to `ProvisionOrFind`. One read, so there is no window between two.
- **The provisioner no longer reads the configuration at all.** Its `PolicyFn` seam is gone rather than left unused: a seam that can read it again is a seam that will, and the defect was exactly that second read.

## Why not carry the version and refuse

The issue offered that alternative. It turns a race into a failed sign-in for an operator who did nothing wrong, and the operator cannot tell it from a real outage. Carrying the policy costs nothing and refuses nobody: the save applies from the next sign-in, which is what an admin saving a configuration expects anyway.

## Out of scope

The login route reads the configuration to build an authorization URL, and the callback reads it again on the way back. Those are two different requests minutes apart, and a configuration that changes between them is an ordinary reconfiguration rather than a race: the exchange fails and the operator signs in again under the new provider.
