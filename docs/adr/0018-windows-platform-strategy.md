# 0018. Windows platform strategy

- Status: Accepted
- Date: 2026-07-02
- Deciders: getvictor

## Context

ADR-0002 shipped the MVP on macOS and Apple Silicon only, and deferred Linux and Windows agents "until after the MVP pilot closes," each to get its own ADR. This is that ADR for Windows. It is prompted by issue #587 (the Windows support epic) and by the market reality that no product is treated as a top-tier EDR without Windows coverage: Windows is where most attack volume and most of the MITRE evaluation surface live, and nearly every "Mac-heavy shop" we pitch still runs a Windows fleet.

A survey of the codebase on 2026-07-02 established that the agent is closer to portable than its macOS heritage suggests. The queue (pure-Go SQLite via modernc), the uploader, enrollment and mTLS, the durable command ledger, the gRPC control client, health reporting, and metrics carry no macOS-specific code and already cross-compile. The macOS coupling is isolated behind build tags: the XPC receiver (`receiver_other.go` is already the non-darwin stub), code-signing evaluation (`codesign_other.go` already stubs non-darwin), the `kill_process` default (`syscall.Kill`), host identity (`agent/hostid`, which shells to `ioreg`), and config path literals. A GOOS=windows build fails today at exactly two sites, both the `syscall.Kill` default value.

The gaps that are not yet portable are on the contract, not the plumbing. The event envelope in `schema/events.json` has no platform discriminator, the hosts view has no OS column, and the process and signing vocabulary is Endpoint Security Framework shaped (`code_signing.team_id`, `cdhash`, `pid_version`, `btm_launch_item_add`). All ten detection rules in `server/rules/internal/catalog/` target macOS tradecraft (launchd, dyld, osascript, Keychain, sudoers), and the engine applies every rule to every event with no platform filter. These are the "audit the envelope before the second platform lands" items ADR-0002 and `best-practices.md` section 2 flagged.

Windows telemetry comes in two tiers, and the choice between them shapes everything downstream:

- **User-mode ETW.** An elevated service can consume Microsoft-Windows-Kernel-Process (process start and stop, image load), Kernel-Network and TcpIp, DNS-Client, Kernel-File, and Kernel-Registry, plus Security event 4688 for process command lines when the audit policy is enabled, and AMSI for script inspection. This tier needs no driver and no membership in any Microsoft program. It cannot block execution before it happens and it is tamperable by an attacker who already has administrative rights.
- **The privileged tier.** An Early Launch Anti-Malware (ELAM) signed driver plus an anti-malware Protected Process Light (PPL) service unlocks the Microsoft-Windows-Threat-Intelligence ETW provider (in-memory injection, suspicious LSASS handle access, credential-theft signals), kernel pre-execution blocking callbacks, and OS-enforced tamper protection. This tier is gated behind the Microsoft Virus Initiative (MVI).

Two external facts make the sequencing non-obvious and are documented in the findings section below: MVI membership is hard for an EDR-only vendor to obtain, and Microsoft is actively moving security products out of the kernel, so a kernel driver written today has a shelf life.

## Decision

Build a Windows agent as a new deployment target for the existing server, agent core, UI, and data plane, phased so that visibility ships first and enforcement depth follows, and started behind a platform-agnostic contract so the second platform does not bake macOS assumptions any deeper.

### Support floor

Windows 11 current and previous annual release (25H2 and 24H2 as of this writing) and Windows Server 2025, on x64 and ARM64. Windows 10, Windows Server 2022, and older are a deliberate non-decision (will not do), and 32-bit x86 is out of scope. This mirrors the ADR-0002 amendment that floored macOS at 26+: a narrow, modern matrix lets the sensor rely on current platform security primitives (native Sysmon, modern ETW providers, VBS and HVCI baselines, WDAC) instead of carrying a decade of legacy quirks and a second QA matrix.

### Phasing

- **Phase 0, platform-agnostic contract (this ADR and its immediate code changes).** Add an optional `platform` field to the event envelope and to the host inventory, and platform-scope the detection rule catalog so every rule declares the platforms it targets and the engine evaluates a rule only against matching events. A missing platform is interpreted as `darwin` forever, so every already-deployed agent keeps working with no release dependency.
- **Phase 1, user-mode ETW sensor.** A Windows build of the portable core running as a Windows service, with an ETW consumer producing exec, exit, network-connect, and DNS-query events, Authenticode verification behind the code-signing seam, `kill_process` via TerminateProcess, an MSI installer, and a TPM-backed agent key via the CNG platform crypto provider (the Windows analogue of the Secure Enclave mTLS decision). The docs will state plainly that this tier is tamperable by an administrative attacker and cannot block execution.
- **Phase 2, Windows detection content.** A rule pack covering Windows tradecraft (encoded PowerShell, LOLBin abuse, Run-key and scheduled-task persistence, service creation, an LSASS-access approximation), each shipping efficacy corpus entries per the repo testing policy.
- **Phase 3, privileged tier.** ELAM-signed driver plus anti-malware PPL service for ETW-TI telemetry, kernel pre-execution blocking (application-control parity with the macOS ESF path), and OS-enforced tamper protection, contingent on MVI membership. The MVI paperwork starts during Phase 1 because it has a long lead time and gates everything in this phase.

The sensor sits behind a swappable interface so the kernel-versus-platform-API decision for Phase 3 can be deferred: if Microsoft's user-mode endpoint security platform covers blocking and tamper protection by the time Phase 3 starts, we build on that API and skip the kernel driver entirely.

### Design-only spec: process identity abstraction

macOS pins process identity across PID reuse with the ESF `pid_version`, and the `processes` table already keys on `(host_id, pid, pid_version)`. Windows has no `pid_version`; the kernel guarantees uniqueness of a process by the pair of its PID and its creation time (a 100-nanosecond FILETIME). Phase 0 defines the platform-neutral key `(host_id, pid, pid_epoch)`, where `pid_epoch` is `pid_version` on macOS and the process creation time (carried as int64 nanoseconds) on Windows. The envelope keeps each platform's native field name in the payload; the process-graph builder maps both into the neutral key so neither vocabulary leaks across a platform boundary. No code lands for this in Phase 0; the payload fields arrive with the Windows sensor in Phase 1.

### Design-only spec: signing abstraction

macOS signing is today's `code_signing` object (`team_id`, `signing_id`, `flags`, `is_platform_binary`) plus `cdhash`. Windows signing is Authenticode: a publisher and issuer, a certificate thumbprint, a WinVerifyTrust verdict, and a catalog-versus-embedded flag (most OS binaries are catalog-signed, so a sensor that ignores catalogs reports System32 as unsigned). Phase 0 defines a discriminated signing object with a per-platform variant and a normalized projection (`verified` boolean and a `signer_display` string) that the UI signing-verdict surfaces and platform-neutral rules consume; a platform-specific rule may still reach the raw variant. The application-control `RuleType` set (CDHASH, SIGNINGID, TEAMID) is the macOS precedent that Windows publisher and thumbprint rule types will mirror in Phase 3. No code lands for this in Phase 0.

### Windows endpoint security platform and MVI eligibility findings

These findings, gathered 2026-07-02, are why Phase 3 is contingent rather than scheduled, and why Phase 1 is driverless.

- **MVI membership is hard for an EDR-only vendor.** Microsoft's published criteria (learn.microsoft.com/en-us/unified-secops/virus-initiative-criteria, updated 2026-03) require a commercially available security solution with real-time malware detection, prevention, and remediation; an active antimalware industry reputation (conference participation, industry-body membership, coverage in AV-Comparatives, OPSWAT, or Gartner); use of Trusted Signing; and an annual independent-lab certification (AV-Comparatives, AV-TEST, SE Labs, or a peer). The language is written for antimalware vendors. An EDR-only product with no real-time prevention engine will face resistance on the real-time-protection and antimalware-reputation criteria. The clarification path is mvi@microsoft.com, and whether we qualify (or must add a minimal antimalware capability to qualify) is an open question that must be resolved before Phase 3, not assumed.
- **ELAM signing requires MVI.** An ELAM driver needs an Early Launch EKU certificate and a WHCP submission through Partner Center, and the submission verifies MVI membership. ELAM plus a PPL service is what unlocks the Microsoft-Windows-Threat-Intelligence ETW provider and boot-time protections.
- **Kernel access is contracting.** From the April 2026 Windows update, cross-signed kernel drivers lose trust and only WHCP-signed drivers load by default (evaluation mode first, enforcement later). Any driver we ship must be WHCP-signed from day one.
- **The industry is moving to user mode.** Microsoft's Windows Resiliency Initiative, announced 2025-06-26 after the 2024 CrowdStrike outage, is building a user-mode Windows endpoint security platform so security products run outside the kernel. As of mid-2026 it is a private preview limited to roughly a dozen MVI partners (CrowdStrike, Bitdefender, ESET, SentinelOne, Sophos, Trellix, Trend Micro, WithSecure among them), with no public API and no announced GA date. A small EDR-only vendor is unlikely to be in the current preview, so the pragmatic path is to build Phase 1 on open ETW and adopt the platform API when it becomes generally available.
- **Driverless is a real tier, and it is getting better on our floor.** Microsoft is shipping Sysmon natively in Windows 11 (Insider preview in late 2025, general availability around H1 2026): an ETW-based, no-vendor-driver source of process, image-load, network, registry, and file events, serviced through Windows Update. Combined with the open Kernel-Process, Kernel-Network, and DNS-Client providers and Security 4688 for command lines, the driverless telemetry gap on Windows 11 24H2+ and Server 2025 is much smaller than folklore suggests. The honest limits remain: no pre-execution blocking, user-mode ETW is tamperable by an administrative attacker, file-event fidelity is lower than a minifilter, and ETW-TI is unreachable without MVI. No tier-1 commercial EDR runs driverless at enterprise scale today, but the platform transition is where the whole industry is heading.

## Consequences

**Good:**

- The agent core is reused, not rebuilt. Queue, uploader, enrollment, control channel, command ledger, health, and metrics are already portable, so Phase 1 is mostly a sensor plus a handful of platform seams, not a second agent.
- The platform contract lands once, additively, and every existing macOS agent keeps working because a missing platform means `darwin`. New actor platforms (Linux next) are then a matter of declaring a value, not reworking the envelope.
- Every detection rule must declare the platforms it targets, enforced at compile time, so a macOS rule can never silently fire on a Windows event and a reviewer cannot merge a rule with no platform attestation.
- Phase 1 ships to a pilot with no dependency on MVI or on a driver-signing program, and the sensor interface keeps the Phase 3 kernel-versus-platform-API choice open.

**Bad:**

- The event envelope, hosts view, and rule engine all gain a platform dimension that macOS code must now carry, and a legacy agent's absent platform is interpreted as `darwin` forever, which is a small permanent compatibility rule.
- `os_version` in the enrollment payload has always carried `runtime.GOOS` ("darwin"), a misnomer. Phase 0 adds a separate `platform` field and deliberately leaves `os_version` as is; making it a real version string ("macOS 26.1", "windows 10.0.26100") needs platform-specific code and is a flagged follow-up, not part of this ADR.
- Phase 3 is contingent on MVI eligibility that we do not yet have and may not obtain as an EDR-only vendor, so the deepest Windows detections (injection, credential theft, pre-execution blocking, OS-enforced tamper protection) are not guaranteed. Phase 1 and Phase 2 deliver a real product without them, but the ceiling is lower than a kernel-tier competitor until this is resolved.
- Driverless Phase 1 is tamperable by an administrative attacker and cannot block execution. This is acceptable for a visibility-first pilot and is exactly what Phase 3 (or the platform API) is meant to fix, but it must be stated to customers, not glossed.

## Alternatives considered

**Ship a kernel driver first for parity with incumbents.** Rejected for now. It requires MVI membership we may not qualify for, a WHCP-signed driver from day one under the April 2026 kernel-trust change, and a multi-quarter investment in a capability Microsoft is actively deprecating for security products. Starting driverless delivers a pilot-ready product in a fraction of the time and keeps the kernel-versus-platform-API decision open.

**Wait for the Windows endpoint security platform to reach general availability and build only on it.** Rejected. It is a private preview with no public API and no GA date, and a small EDR-only vendor is unlikely to be admitted to the preview. Building Phase 1 on open ETW now, behind a swappable sensor interface, means we ship today and adopt the platform API when it lands.

**Put the platform discriminator on the host record only, not on the event.** Rejected. Rule scoping needs the platform in the evaluation hot path, and events reach the engine through a multi-host work queue, so resolving platform per host at evaluation time would mean a lookup (or a join) the stateless multi-replica server (ADR-0010, ADR-0011) and the bounded-context boundary (ADR-0004) make awkward. Carrying platform on the envelope keeps evaluation a pure function of the event batch.

**Support Windows 10 and Server 2022 as well.** Rejected, matching the ADR-0002 posture of a narrow modern floor. Older Windows means a larger QA matrix, weaker default platform security to rely on, and no native Sysmon, for a shrinking population.

**Fold the platform contract and the rule scoping into the macOS envelope opportunistically as the Windows sensor is written.** Rejected. That is the "shallow cross-platform story baked in late" failure ADR-0002 warned against. Landing the contract first, deliberately and with the identity and signing abstractions designed up front, is the right order of operations.

## Amendment (2026-07-03): enforcement without MVI, macOS/Windows feature parity, and language strategy

Three clarifications after the first Windows sensor landed (the ETW process sensor) and after deeper research into what the Microsoft Virus Initiative (MVI) actually gates.

### Enforcement does not require MVI or a kernel driver

The original Decision implied that application control and response actions belong to the privileged Phase 3 tier. That is wrong for the common cases, and the phasing is revised accordingly.

- Network quarantine and host isolation are achievable in user mode via the Windows Filtering Platform (WFP): an elevated service adds high-precedence block filters at the ALE layers with a permit exception for the agent's management channel, which is how commercial EDRs isolate a host. No kernel driver, no MVI.
- Application and execution blocking are achievable without MVI via WDAC (App Control for Business), an OS-enforced allow or deny policy keyed on hash, signer, or path (policy-based, with some update latency); or, for real-time programmatic deny with the agent's own logic, a kernel process-notify callback driver, which needs WHCP signing (an EV certificate plus Partner Center attestation) but still not MVI.
- What MVI actually gates is the anti-tamper and deep-telemetry tier: an ELAM-signed driver, running the agent service as a Protected Process Light so a local administrator cannot disable it, and the Microsoft-Windows-Threat-Intelligence ETW provider (in-memory injection, credential-theft signals). The catch is that WFP and WDAC enforcement are defeatable by an admin-level attacker (WFP-manipulation tools such as EDRSilencer, or a malicious WDAC policy), so MVI is how enforcement becomes tamper-resistant, not how it is obtained.

Revised phasing: basic response actions (WFP isolation, WDAC block) move into the driverless phase alongside telemetry; tamper-resistance and deep detection remain the MVI-gated tier. This maps onto the reserved `isolate` command and the `SendApplicationControl` path already in the codebase, which the Windows sensor can implement via WFP and WDAC without MVI. MVI itself remains a heavy, EDR-only-unfriendly lift (it requires a commercially available real-time antimalware product and an annual independent AV-lab certification), so it is a later track, not an MVP dependency.

### macOS and Windows agents track relative feature parity

Once the Windows agent exists, the macOS and Windows agents are kept at relative feature parity: neither platform is allowed to race ahead. A new capability is designed against the shared event contract and landed on both sensors together (and Linux when it exists), rather than shipping on one platform and backfilling the other later. The shared Go core and the platform sensor seam exist precisely to make parallel per-platform work cheap, and future feature work is expected to target both platforms at once. This parity expectation is now an explicit design constraint on new agent work, not an aspiration.

### Language strategy: Go-first for reuse, Swift where Apple forces it, Rust where needed

- The portable agent (queue, uploader, enrollment, control channel, command ledger, health, metrics, config, process graph, reconciler) and the user-mode sensors are Go, because that is what lets the macOS, Windows, and later Linux agents share the majority of the agent code and the wire contract. Reuse is real today: the entire Go daemon and the server-side pipeline are shared; only the per-OS sensor is not (and cannot be, since it binds an OS-specific telemetry API).
- Swift is used only for the macOS ESF system extension, which Apple requires to link EndpointSecurity.framework inside a sandboxed, entitled, notarized process.
- Rust is the intended language for future Windows components where it is needed: performance-critical or security-sensitive user-mode code (for example a high-volume ETW provider parser, or the tamper-sensitive service). A Windows kernel driver, if the privileged tier is pursued, is C/C++ per the WDK; Rust's place is user mode.
- Go garbage collection and telemetry are not a first-order concern at the event rates these sensors handle (process, network, and DNS events are hundreds to low-thousands per second; modern Go GC pauses are concurrent and sub-millisecond), and ETW's own kernel buffers decouple a brief consumer stall from loss (a slow consumer drops via the session's EventsLost rather than blocking the kernel). The real cost is per-event allocation churn (TDH buffers, string decode, JSON marshal), which is throughput rather than pause and is addressed with allocation discipline (buffer reuse) before any rewrite. Posture: instrument dropped and lost events and GC, keep the ETW callback allocation-light, and reach for Rust surgically for a specific provider that measurement proves too hot, not preemptively. Note the asymmetry the parity goal must account for: on macOS the hot sensor path is Swift (no GC) and Go only relays bytes, whereas on Windows the hot path is Go, so Windows leans on the runtime harder.

## References

- Issue #587 (Windows agent support epic), which this ADR anchors.
- ADR-0002 ([`0002-macos-apple-silicon-mvp-only.md`](0002-macos-apple-silicon-mvp-only.md)): the deferral this ADR discharges, and the narrow-modern-floor posture it mirrors.
- ADR-0004 ([`0004-modular-monolith-bounded-contexts.md`](0004-modular-monolith-bounded-contexts.md)) and ADR-0010 ([`0010-stateless-server.md`](0010-stateless-server.md)): the boundary and statelessness constraints that put platform on the envelope rather than a per-host lookup.
- ADR-0008 ([`0008-selective-esf-subscription.md`](0008-selective-esf-subscription.md)): the macOS telemetry-source decision the Windows ETW tier parallels.
- [`best-practices.md`](../best-practices.md) section 2 (Cross-platform reach): the platform-agnostic-envelope and unified-process-graph TODOs this begins to pay down.
- Microsoft Virus Initiative criteria: https://learn.microsoft.com/en-us/unified-secops/virus-initiative-criteria (updated 2026-03).
- ELAM prerequisites: https://learn.microsoft.com/en-us/windows-hardware/drivers/install/elam-prerequisites.
- Windows Resiliency Initiative: https://blogs.windows.com/windowsexperience/2025/06/26/the-windows-resiliency-initiative-building-resilience-for-a-future-ready-enterprise/ and https://www.cybersecuritydive.com/news/microsoft-windows-resilience-initiative-security-kernel/813416/.
- Cross-signed kernel driver trust removal: https://techcommunity.microsoft.com/blog/windows-itpro-blog/advancing-windows-driver-security-removing-trust-for-the-cross-signed-driver-pro/4504818.
- Native Sysmon in Windows: https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/overview.
- Windows Filtering Platform (user-mode filters for network isolation): https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page.
- WDAC / App Control for Business (OS-enforced application blocking): https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/appcontrol.
- MVI membership application (reviewed monthly): linked from the MVI criteria page above.
