package catalog

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/netip"
	"slices"

	"github.com/fleetdm/edr/server/rules/api"
)

// DNSC2Beacon fires when a suspicious process resolves a domain and then connects to the resolved address, correlating
// all three telemetry streams (exec context + dns_query + network_connect) into one finding. This is the canonical C2
// beacon shape and the literal demonstration of the EDR's three-stream join: no single open-source tool joins exec,
// network, and DNS into one detection.
//
// Reverse-direction trigger (on network_connect, the last link): by the time the connection lands, the process's
// dns_query events are already ingested and materialised, so the join is a single retrospective lookup and the rule
// holds no state between batches (the stateless-server constraint). dns_query and network_connect are both emitted by
// the network extension and share its clock, so their resolve-then-connect correlation is done on timestamp_ns; the
// exec (Endpoint Security, a clock that drifts from the NE per issue #7) is reached only via GetProcessByPID.
//
// Suspicion gate (v1): the originating process MUST be exec'd from a temporary or world-writable path
// (isSuspiciousPath) -- the dropped-payload shape. Ordinary browser traffic that resolves and connects never fires
// because the browser is not a suspicious-context process. A high-entropy (DGA-like) resolved domain raises the finding
// from High to Critical and adds T1568.002. (A script-interpreter-with-non-interactive-parent signal is a documented
// follow-up; the temp-path gate is the precise v1 signal.)
//
// MITRE ATT&CK: T1071.004 (Application Layer Protocol: DNS), plus T1568.002 (Dynamic Resolution: Domain Generation
// Algorithms) when the resolved domain trips the entropy signal.
type DNSC2Beacon struct{}

func (r *DNSC2Beacon) ID() string { return "dns_c2_beacon" }

// Techniques is the union the rule can stamp; a given finding narrows this to the subset that actually applied (every
// finding carries T1071.004; only DGA-domain findings add T1568.002). Procurement and ATT&CK-Navigator export read this
// list, so it is pinned by a test.
func (r *DNSC2Beacon) Techniques() []string {
	return []string{techniqueDNSC2, techniqueDGA}
}

func (r *DNSC2Beacon) Doc() api.Documentation {
	return api.Documentation{
		Title:   "DNS C2 beacon (suspicious process resolves a domain then connects to it)",
		Summary: "Correlates all three streams: a temp/world-writable-path process that resolves a domain (dns_query) and then connects to the resolved address (network_connect).",
		Description: "Fires on the LAST link of the chain -- an outbound network_connect from a process that was exec'd " +
			"out of a temporary or world-writable path AND previously issued a dns_query whose resolved addresses " +
			"include the address being connected to. The single finding cites the dns_query and the network_connect " +
			"and is attributed to the originating process (its exec), so an analyst sees the full exec -> DNS -> " +
			"network chain in one alert.\n\n" +
			"Reverse-direction triggering is deliberate and race-immune: by the time the connection lands, the " +
			"process's DNS resolutions are already ingested, so the rule holds no cross-batch state. dns_query and " +
			"network_connect share the network-extension clock, so the resolve-then-connect window is measured on " +
			"timestamp_ns.\n\n" +
			"A high-entropy (algorithmically generated) resolved domain escalates the finding to Critical and adds the " +
			"DGA technique. Ordinary browser traffic does not fire: the rule gates on a suspicious process exec " +
			"context, which a browser does not satisfy.",
		Severity:   api.SeverityHigh,
		EventTypes: []string{"network_connect", "dns_query", "exec"},
		FalsePositives: []string{
			"A tool legitimately staged to a temp path that fetches a hostname and connects to it -- rare on managed fleets; allowlist the path if it recurs.",
		},
		Limitations: []string{
			"Sees classic UDP/TCP DNS only; encrypted DNS (DoH/DoT) bypasses the proxy and is not correlated.",
			"v1 gates on a temporary/world-writable exec path; a script-interpreter-with-non-interactive-parent signal is a planned extension.",
			"Resolve-then-connect window is bounded (dnsBeaconWindowNs); a beacon that resolves far in advance of connecting is missed by design.",
		},
	}
}

// MITRE technique IDs the rule stamps. Named constants (not inline literals) so the rule body, Techniques(), and the
// per-finding subset all reference one source (Sonar go:S1192).
const (
	techniqueDNSC2 = "T1071.004" // Application Layer Protocol: DNS
	techniqueDGA   = "T1568.002" // Dynamic Resolution: Domain Generation Algorithms
)

const (
	// dnsBeaconWindowNs bounds how long before the connection the matching dns_query may have occurred, on the shared
	// network-extension clock. A beacon resolves and connects within sub-second; 30s is a generous ceiling.
	dnsBeaconWindowNs = int64(30_000_000_000)

	// processLookupSkewPadNs is the forward pad used to retry the process lookup when the exact-time lookup misses.
	// network_connect carries the network-extension clock while the process row carries the Endpoint Security clock; the
	// two drift (issue #7), so a connect timestamp can land just before the ES fork/exec timestamp and bracket to no row.
	// Retrying a few seconds forward absorbs that skew. The exact lookup is tried first, so the pad only affects the miss.
	processLookupSkewPadNs = int64(5_000_000_000)

	// ingestLookupPadNs pads the ingested-time bound on the network/DNS query so batch/ingest jitter between the
	// dns_query and the connection (both network-extension events, ingested within seconds) can't fall outside the range.
	// The precise resolve-then-connect window is still enforced in-memory on timestamp_ns.
	ingestLookupPadNs = int64(10_000_000_000)

	// dgaMinLabelLen and dgaEntropyBitsPerChar gate the DGA severity booster. A label must be at least this long and
	// carry at least this much Shannon entropy per character to read as algorithmically generated. Tuned empirically
	// against the efficacy corpus and captured benign traffic; this is a severity booster, not a firing gate, so a
	// misclassification only over- or under-escalates an already-suspicious temp-path beacon.
	dgaMinLabelLen        = 12
	dgaEntropyBitsPerChar = 3.5
)

// networkConnectPayload is declared in suspicious_exec.go (PID, Direction, RemoteAddress, RemotePort); reused here.

type dnsQueryPayload struct {
	PID               int      `json:"pid"`
	QueryName         string   `json:"query_name"`
	ResponseAddresses []string `json:"response_addresses"`
}

func (r *DNSC2Beacon) Evaluate(ctx context.Context, events []api.Event, s api.GraphReader) ([]api.Finding, error) {
	// One process commonly emits several outbound connections; emit one finding per process per batch. The engine
	// additionally dedups on ProcessID across batches.
	seenPID := map[int]struct{}{}
	var findings []api.Finding
	for _, evt := range events {
		f, pid, err := r.evalEvent(ctx, evt, s, seenPID)
		if err != nil {
			return nil, err
		}
		if f != nil {
			findings = append(findings, *f)
			seenPID[pid] = struct{}{}
		}
	}
	return findings, nil
}

// evalEvent inspects one event. On a match it returns (finding, pid, nil); pid is the connecting process's PID for
// batch-level dedup.
func (r *DNSC2Beacon) evalEvent(
	ctx context.Context, evt api.Event, s api.GraphReader, seenPID map[int]struct{},
) (*api.Finding, int, error) {
	if evt.EventType != "network_connect" {
		return nil, 0, nil
	}
	var conn networkConnectPayload
	if err := json.Unmarshal(evt.Payload, &conn); err != nil {
		return nil, 0, nil
	}
	// Only outbound connections beacon. Inbound flows have a peer remote_address that the local process never resolved.
	if conn.Direction != "outbound" || conn.RemoteAddress == "" {
		return nil, 0, nil
	}
	if _, dupe := seenPID[conn.PID]; dupe {
		return nil, 0, nil
	}

	proc, err := lookupProcessSkewTolerant(ctx, s, evt.HostID, conn.PID, evt.TimestampNs)
	if err != nil {
		return nil, 0, fmt.Errorf("get pid %d: %w", conn.PID, err)
	}
	if proc == nil {
		// Race against materialisation; same defensive shape as the other correlation rules.
		return nil, 0, nil
	}
	// Suspicion gate: only a process exec'd from a temp / world-writable path is a candidate. This is what keeps benign
	// browser resolve-then-connect traffic from firing.
	if !isSuspiciousPath(proc.Path) {
		return nil, 0, nil
	}

	// Retrieve the pid's network/DNS events, then bound the correlation in-memory on timestamp_ns. network_connect +
	// dns_query share the NE clock, so timestamp_ns proximity is sound here even though GetNetworkEventsForProcess
	// filters ingested_at_ns (which exists for ES/NE cross-source drift, issue #7). The ingested-time range is bounded
	// around this connection's ingest time to keep the DB scan tight for long-lived pids; it falls back to the full
	// range when the connection's ingest time is unset (e.g. fixture replay), so the precise in-memory window still runs.
	netEvents, err := s.GetNetworkEventsForProcess(ctx, evt.HostID, conn.PID, ingestedLookupRange(evt.IngestedAtNs))
	if err != nil {
		return nil, 0, fmt.Errorf("get network events for pid %d: %w", conn.PID, err)
	}

	dnsEvt, queryName := selectResolvingQuery(netEvents, conn.RemoteAddress, evt.TimestampNs)
	if dnsEvt == nil {
		return nil, 0, nil
	}

	severity := api.SeverityHigh
	techniques := []string{techniqueDNSC2}
	if looksLikeDGADomain(queryName) {
		severity = api.SeverityCritical
		techniques = []string{techniqueDNSC2, techniqueDGA}
	}

	return &api.Finding{
		HostID:      evt.HostID,
		RuleID:      r.ID(),
		Severity:    severity,
		Title:       "DNS C2 beacon",
		Description: fmt.Sprintf("%s resolved %s and connected to %s", proc.Path, queryName, conn.RemoteAddress),
		ProcessID:   proc.ID,
		EventIDs:    []string{dnsEvt.EventID, evt.EventID},
		Techniques:  techniques,
	}, conn.PID, nil
}

// lookupProcessSkewTolerant resolves the process for (hostID, pid) at the connection's timestamp, retrying a short interval forward if
// the exact-time lookup misses. The connection carries the network-extension clock while the process row carries the Endpoint Security
// clock; the two drift (issue #7), so a connect timestamp can land just before the ES fork/exec timestamp and bracket to no row. The
// exact lookup is tried first (so a reused pid resolves to the right generation in the common case); the forward retry only runs on a miss.
func lookupProcessSkewTolerant(ctx context.Context, s api.GraphReader, hostID string, pid int, atNs int64) (*api.Process, error) {
	proc, err := s.GetProcessByPID(ctx, hostID, pid, atNs)
	if err != nil {
		return nil, err
	}
	if proc != nil {
		return proc, nil
	}
	return s.GetProcessByPID(ctx, hostID, pid, atNs+processLookupSkewPadNs)
}

// ingestedLookupRange returns the ingested-time range for the pid's network/DNS query. When the connection's ingest time is known it
// bounds the scan to [connectIngestedNs - dnsBeaconWindowNs - pad, connectIngestedNs + pad] so a long-lived pid's history isn't scanned
// wholesale; the precise resolve-then-connect window is enforced in-memory on timestamp_ns. When the ingest time is unset (0, e.g.
// fixture replay) it returns the full range so the in-memory correlation still sees every candidate row.
func ingestedLookupRange(connectIngestedNs int64) api.TimeRange {
	if connectIngestedNs <= 0 {
		return api.TimeRange{FromNs: 0, ToNs: math.MaxInt64}
	}
	return api.TimeRange{
		FromNs: connectIngestedNs - dnsBeaconWindowNs - ingestLookupPadNs,
		ToNs:   connectIngestedNs + ingestLookupPadNs,
	}
}

// selectResolvingQuery scans the pid's network/DNS events for the dns_query that resolved remoteAddr and preceded the connection at
// connectTSNs within the beacon window. When several queries match (e.g. two domains resolving to the same CDN IP) the most recent is
// chosen, with ties broken on the lexicographically smallest query name so attribution is deterministic. Returns (nil, "") when no
// query resolved the connected address.
func selectResolvingQuery(netEvents []api.Event, remoteAddr string, connectTSNs int64) (*api.Event, string) {
	var best *api.Event
	var bestName string
	for i := range netEvents {
		e := &netEvents[i]
		if e.EventType != "dns_query" {
			continue
		}
		// The resolution must precede the connection and fall inside the window (both on the shared NE clock).
		if e.TimestampNs > connectTSNs || connectTSNs-e.TimestampNs > dnsBeaconWindowNs {
			continue
		}
		var q dnsQueryPayload
		if err := json.Unmarshal(e.Payload, &q); err != nil {
			continue
		}
		if !addressResolved(remoteAddr, q.ResponseAddresses) {
			continue
		}
		if best == nil || e.TimestampNs > best.TimestampNs ||
			(e.TimestampNs == best.TimestampNs && q.QueryName < bestName) {
			best = e
			bestName = q.QueryName
		}
	}
	return best, bestName
}

// addressResolved reports whether remoteAddr appears in addrs, comparing parsed IPs (via net/netip, allocation-free and
// zone-aware) so equivalent IPv6 forms (zero compression, case, v4-in-v6) match. Unmap normalizes v4-mapped v6 to v4 on
// both sides. Falls back to an exact string compare when remoteAddr is not a parseable IP.
func addressResolved(remoteAddr string, addrs []string) bool {
	target, err := netip.ParseAddr(remoteAddr)
	if err != nil {
		return slices.Contains(addrs, remoteAddr)
	}
	target = target.Unmap()
	for _, a := range addrs {
		if ip, parseErr := netip.ParseAddr(a); parseErr == nil && ip.Unmap() == target {
			return true
		}
	}
	return false
}

// looksLikeDGADomain reports whether the most significant label of the domain reads as algorithmically generated: at least
// dgaMinLabelLen characters carrying at least dgaEntropyBitsPerChar bits of Shannon entropy per character. Pure + total so it is
// unit-tested without an XPC peer or a store.
func looksLikeDGADomain(domain string) bool {
	label := mostSignificantLabel(domain)
	if len(label) < dgaMinLabelLen {
		return false
	}
	return shannonEntropyBitsPerChar(label) >= dgaEntropyBitsPerChar
}

// mostSignificantLabel returns the longest dot-separated label of the domain (the label most likely to carry a DGA
// payload; the TLD and common second-level labels are short and stable). Trailing dots are ignored.
func mostSignificantLabel(domain string) string {
	var longest string
	start := 0
	for i := 0; i <= len(domain); i++ {
		if i == len(domain) || domain[i] == '.' {
			label := domain[start:i]
			if len(label) > len(longest) {
				longest = label
			}
			start = i + 1
		}
	}
	return longest
}

// shannonEntropyBitsPerChar returns the Shannon entropy (bits per character) of s. An empty string is 0. Counts runes in
// a single pass (no []rune allocation) and pre-sizes the map to avoid resizing.
func shannonEntropyBitsPerChar(s string) float64 {
	if s == "" {
		return 0
	}
	counts := make(map[rune]int, len(s))
	var total int
	for _, c := range s {
		counts[c]++
		total++
	}
	n := float64(total)
	var entropy float64
	for _, c := range counts {
		p := float64(c) / n
		entropy -= p * math.Log2(p)
	}
	return entropy
}
