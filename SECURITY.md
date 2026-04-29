# Security policy

Fleet EDR is a security product. We take vulnerabilities seriously and
welcome reports from researchers, customers, and the wider community.

## Supported versions

We patch the most recent released minor only. Pilot releases (`v0.x.y-rc.*`)
are pre-GA and receive fixes on a best-effort basis; once `v1.0.0` ships we
will publish a formal support window here.

| Version    | Status              | Security fixes |
| ---------- | ------------------- | -------------- |
| `0.1.x-rc` | Pilot / pre-GA      | Best-effort    |
| `< 0.1`    | Unsupported         | None           |

## Reporting a vulnerability

**Please do not open a public GitHub issue for security bugs.** Use GitHub's
private vulnerability reporting instead: visit
<https://github.com/getvictor/fleet-edr/security/advisories/new>. This
creates an embargoed draft advisory that only the maintainers and you can
see, and is the only channel we accept reports through.

When you report, please include:

- The component (server, agent, system extension, network extension, UI).
- Affected version(s), commit SHA, or release tag.
- A proof-of-concept or clear reproduction steps.
- The impact you observed, and any workarounds you found.

We will acknowledge receipt within **2 business days**. We aim to publish a
fix within **30 days** for high-severity findings, longer for low-severity
ones, and will keep you updated on progress along the way. After a fix
ships we will credit you in the advisory unless you prefer to remain
anonymous.

## Out of scope

The following classes of finding are not security vulnerabilities for this
project and do not need to be reported privately:

- Issues that require physical access to an unlocked, enrolled Mac.
- Findings that depend on a user already holding root or
  `kTCCServiceSystemPolicyAllFiles` (Full Disk Access) on the endpoint.
- Reports that the agent is detected by EDR/AV products on managed hosts —
  the agent does not attempt to evade detection.
- Denial of service from a single authorised host against its own server
  (e.g. flooding `/api/events` with valid tokens). DoS that crosses
  tenant boundaries or affects other hosts is in scope.
- Findings against `claude/`, scratch, or `tmp/` directories — these are
  developer aids, not shipped artifacts.

Thank you for helping keep Fleet EDR's users safe.
