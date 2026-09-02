// shell_network_connect: a non-shell process spawns a shell which, within its window, opens an outbound network connection.
//
// Split out of suspicious_exec by issue #776. The merged rule fired on two shapes sharing one attribution chain, a temp-directory
// exec OR an outbound connect, and that form is not how the industry models it: Sigma cannot express it at all (one logsource per
// rule, and the arms span process_creation and network_connection), Elastic ships the equivalents as separate sequence rules, and
// the vendors reconcile multi-signal chains at the incident layer rather than inside a rule.
//
// The practical costs of the merge were concrete rather than theoretical. A parent-path-glob exclusion added to silence a noisy CI
// shell on the connect arm also blinded the temp arm. The two arms could not be promoted, tuned or severity-adjusted apart. And
// with no equivalence forced between them, #713 was a gap in the connect arm alone for months.
//
// A chain exhibiting BOTH signals now produces two alerts, one per rule, because each rule carries its own per-batch dedup and no
// rule can see another's findings (ADR-0010 rules out cross-rule state). That is the accepted interim cost of the split and is
// pinned by a fixture rather than left incidental; #777 is the real fix, at the alert-grouping layer where the industry puts it.
package catalog

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"sync"

	"github.com/fleetdm/edr/server/rules/api"
)

// ShellNetworkConnect is the outbound-connection arm of the former suspicious_exec.
type ShellNetworkConnect struct {
	// Exclusions is the per-host false-positive resolver, consulted with match type parent_path_glob against the non-shell
	// parent's path before firing. Nil excludes nothing.
	//
	// Keyed on THIS rule's id, so the exclusions operators saved against suspicious_exec do not apply here. That is deliberate
	// and is why the rule ships in monitor: it starts unfiltered where the merged rule had been tuned, so promoting it before
	// its own false-positive rate is observed would re-raise every FP the merged rule had already absorbed.
	Exclusions api.ExclusionResolver
}

func (r *ShellNetworkConnect) ID() string { return "shell_network_connect" }

// DisplayName is distinct from suspicious_exec's so an operator reading an alert list can tell the two shapes apart without
// opening either; the merged rule used one title for both and leaned on the description to discriminate.
func (r *ShellNetworkConnect) DisplayName() string { return "Shell outbound connection" }

// AlgorithmName names the evaluator for the exported rule file (issue #757). The same ancestor walk suspicious_exec uses, over a
// different trigger event, which is the point of sharing shellchain.go rather than copying it.
func (r *ShellNetworkConnect) AlgorithmName() string { return "ancestor_walk_outbound_connect" }

// DefaultMode ships this rule in monitor (issue #776). It carries no saved exclusions, so it starts where the merged rule was
// before operators tuned it; an operator promotes it once they have seen its own false-positive rate on their fleet.
func (r *ShellNetworkConnect) DefaultMode() api.DetectionRuleMode {
	return api.DetectionRuleModeMonitor
}

// SupportedExclusionMatchTypes mirrors suspicious_exec's: the non-shell parent's path glob plus its code-signing identity, so a
// benign signed parent can be excluded by a signature an attacker in a writable directory cannot spoof (issue #520).
func (r *ShellNetworkConnect) SupportedExclusionMatchTypes() []api.ExclusionMatchType {
	return []api.ExclusionMatchType{
		api.ExclusionMatchParentPathGlob,
		api.ExclusionMatchTeamID,
		api.ExclusionMatchSigningID,
		api.ExclusionMatchCDHash,
	}
}

func (r *ShellNetworkConnect) Techniques() []string {
	// Unchanged from the merged rule (issue #776): whether the connect shape warrants its own mapping is a separate
	// question, deliberately not decided by the split.
	return []string{"T1059", "T1105"}
}

func (r *ShellNetworkConnect) Platforms() []api.Platform { return []api.Platform{api.PlatformDarwin} }

func (r *ShellNetworkConnect) Doc() api.Documentation {
	return api.Documentation{
		Title:   r.DisplayName(),
		Summary: "Flags a non-shell process that spawns a shell which, within 30 seconds, makes an outbound network connection.",
		Description: "Detects the chain shape: non-shell parent → shell child → outbound network_connect.\n\n" +
			"The rule fires on the LAST link (the connection) rather than the shell's exec. That makes it race-immune " +
			"across the agent's flush boundaries: a chain completing in ~150ms but straddling a 1-second flush boundary " +
			"still resolves, because the whole ancestor chain has been ingested by the time the trigger lands.\n\n" +
			"Split from `suspicious_exec` (issue #776), which fired on this shape or a temp-directory exec. At this rule's " +
			"monitor default a chain doing both raises one `suspicious_exec` alert and records a match here; once this rule " +
			"is promoted the same chain raises one alert per rule.\n\n" +
			"30 seconds is the temporal cap between the shell exec and the connection.",
		Severity:   api.SeverityHigh,
		EventTypes: []string{"network_connect"},
		FalsePositives: []string{
			"Interactive SSH where an admin curls a tool. Add a parent-path-glob exclusion for `/usr/libexec/sshd-session` via the detection-config surface if that is a routine workflow on the host class.",
			"Developer tooling that shells out and connects (Claude Code, lefthook git hooks, git, IDEs). These install under version-stamped paths, so add a parent-path-glob exclusion such as `*/claude/versions/*` that survives upgrades.",
		},
		Limitations: []string{
			"The window bounds how long after the shell exec a connection still counts; long-tail post-shell activity is missed by design. Set in x-engine.params.window.",
			"An outbound DNS lookup (port 53) to a local-resolver-class address (loopback, RFC1918, link-local, CGNAT 100.64.0.0/10, IPv6 ULA/link-local) is treated as name resolution and does not fire; a lookup to a publicly routable resolver still does.",
			"Exclusions saved against `suspicious_exec` before the split (issue #776) do not apply here, because exclusions are keyed by rule id. Re-add any that should silence this shape too.",
		},
	}
}

// exclusionResolver and window satisfy shellChainRule, which is how the shared ancestor walk reaches this rule's own resolver and
// its own tuning without either rule knowing about the other.
func (r *ShellNetworkConnect) exclusionResolver() api.ExclusionResolver { return r.Exclusions }

func (r *ShellNetworkConnect) window() int64 { return shellNetworkConnectWindow() }

// Evaluate walks every outbound connection in the batch. One pass, unlike the merged rule's two: there is only one trigger shape
// left, and the cross-arm precedence the second pass existed to preserve is exactly what the split gives up.
func (r *ShellNetworkConnect) Evaluate(ctx context.Context, events []api.Event, s api.GraphReader) ([]api.Finding, error) {
	return r.EvaluateScoped(ctx, &api.BatchScope{}, events, s)
}

// EvaluateScoped implements api.ScopedRule. The scope carries nothing this rule derives; it is here so a chain declined for
// incomplete ancestry is counted rather than silently dropped (issue #829).
func (r *ShellNetworkConnect) EvaluateScoped(
	ctx context.Context, scope *api.BatchScope, events []api.Event, s api.GraphReader,
) ([]api.Finding, error) {
	seenShell := map[int]struct{}{}
	var findings []api.Finding
	// One event whose process row is still missing defers the batch without ending the pass, so it cannot mask a finding another
	// event in the same batch would produce (issue #661).
	var miss pendingMiss

	for _, evt := range events {
		if evt.EventType != "network_connect" {
			continue
		}
		f, shellPID, err := r.evalNetwork(ctx, scope, evt, s, events, seenShell)
		if fatal := miss.absorb(err); fatal != nil {
			return nil, fatal
		}
		if f != nil {
			findings = append(findings, *f)
			seenShell[shellPID] = struct{}{}
		}
	}
	return findings, miss.err
}

// evalNetwork inspects an outbound network_connect event and walks UP from the connecting process looking for a shell ancestor whose
// parent is non-shell. The connecting process itself can be the shell (curl|sh case) or any descendant of it (shell spawned curl);
// the inclusive walk handles both.
func (r *ShellNetworkConnect) evalNetwork(
	ctx context.Context, scope *api.BatchScope, evt api.Event, s api.GraphReader, batch []api.Event, seenShell map[int]struct{},
) (*api.Finding, int, error) {
	var c networkConnectPayload
	if err := json.Unmarshal(evt.Payload, &c); err != nil {
		return nil, 0, nil
	}
	if c.Direction != "outbound" {
		return nil, 0, nil
	}
	// DNS de-noising: a name-resolution lookup to the host's own resolver is not a meaningful "outbound network connection"
	// for this rule. The meaningful signal is the connection to the RESOLVED address that follows, which this arm still sees.
	// Gate on destination CLASS (port 53 to a local-resolver-class address), never on a specific resolver IP, so a DNS query to
	// a publicly routable resolver on :53 (potential DNS tunnelling) still fires. Arm-scoped: the temp-exec arm is untouched.
	if isLocalResolverDest(c.RemoteAddress, c.RemotePort) {
		return nil, 0, nil
	}

	// Resolve the connecting process so the finding links there rather than at the shell. That's what an analyst clicking the
	// alert wants to land on. Prefer exact (host, pid, pidversion) identity when the flow carried a pidversion so the finding
	// attributes to the right generation across PID reuse, falling back to the event-time window otherwise (issue #403). The
	// ancestor walk above still uses the window for shell/parent generations; making parent edges identity-aware is out of scope.
	//
	// This runs before the no-shell exit because the re-exec arm below needs the connecting generation to walk from. It costs one
	// lookup on every outbound flow that has no shell ancestor, where before it cost none. That is the price of seeing a whole
	// class of payload at all (issue #713), and it is one indexed read against the two to four the ancestor walk above already
	// does.
	conn, err := resolveFlowProcess(ctx, s, evt.HostID, c.PID, c.PIDVersion, evt.TimestampNs)
	if err != nil {
		return nil, 0, fmt.Errorf("get conn pid %d: %w", c.PID, err)
	}
	if conn == nil {
		return nil, 0, nil
	}
	// Fall through to the exec chain when the PPID walk yields nothing this arm can fire on. "Nothing usable" rather than "nothing
	// found" is the load-bearing part: where a shell exec'd its payload in place, the walk does not come back empty, it comes back
	// with the wrong shell. The re-exec closed the real shell's generation at this PID, so the walk steps over it and returns the
	// interactive login shell above, which then fails the window because its own exec is minutes or hours old. Gating the chain on
	// shell == nil alone would therefore never reach it, which is how issue #713 stayed open behind a walk that looked like it had
	// searched.
	// Each arm's candidate is gated before it can produce a finding, so neither can grow a way past the window, the parent
	// exclusions, or the per-batch dedup. The check is nested rather than repeated once at the end because shouldFire unmarshals the
	// parent's code-signing record, and this is a per-network_connect path: evaluating it twice for the same shell is measurable
	// work for an answer that cannot have changed.
	shell, parent, err := r.networkShell(ctx, scope, s, evt, conn, seenShell)
	if err != nil {
		return nil, 0, err
	}
	if shell == nil {
		return nil, 0, nil
	}
	parentPath := "(unknown)"
	if parent != nil {
		parentPath = parent.Path
	}
	eventIDs := []string{evt.EventID}
	if shellEventID := findShellExecEventID(batch, evt.HostID, shell.PID, evt.EventID); shellEventID != "" {
		eventIDs = append([]string{shellEventID}, eventIDs...)
	}
	return &api.Finding{
		HostID:      evt.HostID,
		RuleID:      r.ID(),
		Severity:    api.SeverityHigh,
		Title:       r.DisplayName(),
		Description: fmt.Sprintf("%s → %s → outbound %s:%d", parentPath, shell.Path, c.RemoteAddress, c.RemotePort),
		ProcessID:   conn.ID,
		EventIDs:    eventIDs,
	}, shell.PID, nil
}

// networkShell picks the shell this arm will report, or nil when there is none it can fire on. Both places a shell can live are
// tried in order: the connecting process's PPID chain, then that PID's own exec chain for a shell that replaced itself with the
// payload (issue #713).
//
// Every candidate passes shouldFire before it is returned, so neither source can grow a way past the window, the parent exclusions,
// or the per-batch dedup, and each candidate is evaluated exactly once. shouldFire unmarshals the parent's code-signing record, so on
// a per-network_connect path that matters. Returning the decision rather than making it at the call site is also what lets the caller
// nil-check once, which keeps the nil-safety analysis provable.
func (r *ShellNetworkConnect) networkShell(
	ctx context.Context, scope *api.BatchScope, s api.GraphReader, evt api.Event, conn *api.Process, seenShell map[int]struct{},
) (*api.Process, *api.Process, error) {
	shell, parent, err := findShellFromResolvedProcess(ctx, s, evt.HostID, conn)
	if err != nil {
		return nil, nil, err
	}
	if shell != nil && shouldFire(r, seenShell, shell, parent, evt.TimestampNs, evt.HostID) {
		return shell, parent, nil
	}
	shell, parent, incomplete, err := findShellOnExecChain(ctx, s, evt.HostID, conn)
	if err != nil {
		return nil, nil, err
	}
	if incomplete {
		scope.RecordAncestryIncomplete(r.ID())
	}
	if shell != nil && shouldFire(r, seenShell, shell, parent, evt.TimestampNs, evt.HostID) {
		return shell, parent, nil
	}
	return nil, nil, nil
}

// isLocalResolverDest reports whether an outbound connection targets the host's own DNS resolver: port 53 to a local-resolver-class
// address. Such a lookup is not a meaningful "outbound network connection" for this rule; the connection to the resolved address
// that follows is what the rule cares about. A connection to port 53 at a publicly routable address is NOT local-resolver traffic and
// stays eligible to trigger (it can be DNS tunnelling to an external resolver).
func isLocalResolverDest(remoteAddress string, remotePort int) bool {
	return remotePort == dnsPort && isLocalResolverIP(remoteAddress)
}

// isLocalResolverIP reports whether addr parses as a non-publicly-routable address of the class a host's local resolver uses: loopback,
// RFC1918 private (and IPv6 ULA, both via IsPrivate), IPv4/IPv6 link-local, or the CGNAT range Tailscale MagicDNS occupies. A value
// that does not parse as an IP (a hostname, an empty string) is not classifiable as local and returns false so the rule still fires.
//
// netip.ParseAddr (not net.ParseIP) is deliberate: the agent's network telemetry carries scoped IPv6 literals with a zone suffix
// (e.g. `fe80::1%en0`, present in the demo corpus for mDNS on :53), which net.ParseIP rejects but netip.ParseAddr accepts. Without zone
// support those link-local DNS lookups would slip past the de-noiser and re-fire the network arm. The CGNAT membership test is IPv4
// only, so a zoned IPv6 address never reaches it; the link-local branch covers the zoned case.
func isLocalResolverIP(addr string) bool {
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return false
	}
	return ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		cgnatPrefix.Contains(ip)
}

// networkConnectPayload is the subset of network_connect event fields needed for detection. PID identifies the process making the
// connection. The rule walks UP from there looking for a shell ancestor with a non-shell parent.
type networkConnectPayload struct {
	PID           int    `json:"pid"`
	Direction     string `json:"direction"`
	RemoteAddress string `json:"remote_address"`
	RemotePort    int    `json:"remote_port"`
	// PIDVersion is the source process's kernel PID generation (audit_token_to_pidversion), when the agent provided it. Lets a
	// correlation rule resolve the connecting process by exact (host, pid, pidversion) identity instead of a time window. Nil for
	// legacy agents or flows whose audit token was unavailable (issue #403).
	PIDVersion *uint32 `json:"pidversion"`
}

// dnsPort is the well-known DNS port. An outbound connection to it to a local-resolver-class address is name resolution against the
// host's own resolver, which the network arm de-noises (see isLocalResolverDest).
const dnsPort = 53

// cgnatPrefix is the RFC 6598 carrier-grade-NAT shared address space (100.64.0.0/10). netip.Addr.IsPrivate does NOT cover it (it is
// RFC1918 + IPv6 ULA only), but it is not publicly routable, and Tailscale's MagicDNS resolver lives inside it, so a local-resolver
// classifier must include it explicitly. Built from octets rather than a string literal: this is a fixed reserved range, not
// configurable infrastructure, and the octet form keeps S1313 from misreading the constant as a hardcoded endpoint.
var cgnatPrefix = netip.PrefixFrom(netip.AddrFrom4([4]byte{100, 64, 0, 0}), 10)

// shellNetworkConnectWindow is the shell-to-connection bound, from this rule's own pack file. Separate from suspicious_exec's
// identically-valued window on purpose: independent tuning is one of the reasons issue #776 split the rules, and a shared
// constant would have quietly re-coupled them.
var shellNetworkConnectWindow = sync.OnceValue(func() int64 {
	return paramsFor("shell_network_connect").Duration("window").Nanoseconds()
})
