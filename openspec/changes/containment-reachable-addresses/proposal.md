# Operators choose what a contained host can still reach

Issue #1059. Containment ships a fixed lifeline: a contained host keeps loopback, DHCP, resolution of the server name, and its connection to the EDR server. Nothing else. An incident responder who contains a host usually still needs a few systems to reach it, an MDM or remediation server, a forensic collection share, a VPN concentrator, and today containment cuts those off along with the intruder.

This is what comparable products offer. CrowdStrike Falcon lets an operator add addresses that stay reachable during network containment, and Microsoft Defender for Endpoint offers a selective isolation that keeps chosen applications connected.

## What changes

This is the first of three changes, and it is the server half: the set exists, is edited, and is audited. Nothing is delivered to a host yet, so it lands on its own without changing what any contained host can reach.

- **A deployment-wide set of reachable addresses**, one row holding the whole list, versioned as a whole and replaced whole. The shape is the watched-path set's (issue #998), which is the same thing: a deployment-wide set pushed to hosts and versioned so a host can say which one it holds.
- **Validation that keeps the allowance from becoming an exemption.** A floor on how broad any one range may be, rather than a list of forbidden prefixes, because 0.0.0.0/1 and 128.0.0.0/1 are 0.0.0.0/0 written twice. The floors sit where a legitimate operator range still fits: 10.0.0.0/8 for IPv4, a /32 site allocation for IPv6.
- **A reason, audited, and its own permission.** Widening this set is the one edit that weakens a containment already in force, so it is audited like a containment and gated on a permission fewer roles hold than containment itself, with the same reauthentication the host commands require.

## Out of scope for this change

Delivering the set to hosts and enforcing it, which is the next change: the set rides the containment command payload, and a host holding a stale version stops counting as current, so the catch-up that already exists re-queues it. The console surface follows that. Per-host sets and application-based exceptions are out of scope for the issue.

## What this deliberately does not do

It does not refuse SETS whose union is too broad, only individual ranges. Interval arithmetic over two address families is a solver, and the operator it would protect against can already write a reason and is already in the audit trail. The floor and the entry cap bound the worst case; the console showing an operator what a set covers is the honest answer to a set that is too wide.
