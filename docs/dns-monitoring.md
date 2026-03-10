# DNS monitoring on macOS

See https://fleetdm.com/guides/monitor-dns-traffic-on-macos for background
on how DNS works on macOS, encrypted DNS challenges, and mitigation
strategies.

## Implementation notes for this EDR

- **NEFilterDataProvider** (`network_connect` events): the `remoteHostname`
  property provides hostname info for connections without separate DNS
  capture. Works reliably for WebKit-based apps but may only return IP
  addresses for Chromium-based browsers.

- **NEDNSProxyProvider** (`dns_query` events): intercepts queries
  before `mDNSResponder` sends them upstream. Must forward queries to an
  upstream resolver since it replaces the system resolver in the chain.
  Reference implementation: https://github.com/objective-see/DNSMonitor
