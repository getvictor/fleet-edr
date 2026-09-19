# The agent reads its proxy from its own configuration

Issue #1117. `agent/com.fleetdm.edr.agent.plist` tells the reader that all tunables come from `/etc/fleet-edr.conf`, and that is true for the agent's own settings: `config.layeredGetenv` consults the process environment first and falls back to the conf-file map. But the proxy came from `http.ProxyFromEnvironment`, which reads the real process environment, so a `HTTPS_PROXY` line in that file reached nothing. `agent/config` carried no proxy field for it to land in either.

Found during the VM QA for #1110: with the proxy in the conf file, the SOCKS5 proxy logged zero connections while the agent talked to the server normally. Moving the same line into the launchd plist's `EnvironmentVariables` made every connection go through it.

Nothing in `docs/` told an operator where to put it, so the only discoverable place was the file the plist names, which is the one place it did not work.

## What changes

- **`config.ProxyConfig`**, read through the same layered lookup as every other setting, under the conventional `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY` names in either case. The process environment still wins, so one host can be pointed elsewhere without editing the file.
- **The rules are `x/net/http/httpproxy`'s**, the package `net/http` builds `ProxyFromEnvironment` on, so the scheme handling and `NO_PROXY` matching are the ones an operator already expects rather than a second interpretation of the same variables.
- **All four places that pick a proxy now take it from there**: the shared agent transport (uploads, command polling, token refresh), enrollment, the address the containment lifeline pins, and the control channel.
- **`controlDialOptions` lost its proxy parameter.** It already took `cfg`, and two sources for one decision is how the control channel ends up on a different proxy from the uploads.
- **Operator documentation**, which did not exist: `docs/operations.md` now has a section on reaching the server through a proxy, including that a contained host keeps reaching it.

## Why all or nothing

A proxy covering only some of the agent's traffic is worse than none. The covered part hides the uncovered part, and the containment lifeline would pin an address the rest of the agent was not dialing, which would leave a contained host unable to reach the server at all. The delta says this normatively rather than leaving it as an implementation detail.

## Out of scope

- Any proxy setting the agent does not already understand by convention, such as a per-destination proxy or an authenticated proxy scheme beyond what the address itself carries.
