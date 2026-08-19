//go:build integration

// Process-detail flow attribution (issue #716). The panel used to ask for every flow on a pid inside an ingest-time window derived
// from the process lifetime, which dropped the flow an alert had fired on: a flow and its process's exit travel up the agent uploader
// in separate batches, so a short-lived process's flow routinely ingests AFTER its own exit. Measured on dogfood alert 785, the flow
// ingested 3.5s past its own stamp, 2.0s past the window's 1s upper pad, and the panel read "No network activity" for the very
// connection under investigation. Worse, a sibling generation of the same pid that had not exited carried an open-ended window and
// served the flow instead, so it showed under the generation that did not own it.

package tests

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/detection/bootstrap"
)

// spec:server-rest-api/per-process-detail-with-re-exec-chain/a-flow-that-ingests-after-its-process-exited-is-still-attributed-to-it
// spec:server-rest-api/per-process-detail-with-re-exec-chain/a-sibling-generation-of-the-same-pid-does-not-claim-the-flow
//
// End to end through GetProcessDetail, the call the panel makes. The re-exec chain gives one pid two generations with distinct
// pidversions: the first exits, the second stays live. The flow carries the FIRST generation's pidversion, so it must surface on that
// generation's detail even though it arrives after that generation exited, and must not surface on the live one.
func TestProcessDetail_FlowAttributedToOwningGenerationDespiteIngestLag(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	ctx := t.Context()

	const (
		host = "h-716-detail"
		pid  = 51865
	)
	now := time.Now().UnixNano()
	ms := int64(time.Millisecond)

	// Two generations of one pid via PID REUSE, so each has its own fork time and the as-of read can select either. Generation 1
	// (pidversion 121027) execs bash, connects out, and exits; the pid is then reused by generation 2 (121026), which stays live.
	//
	// Reuse rather than a re-exec chain is deliberate: a re-exec preserves the original fork_time_ns across generations, and
	// GetProcessByPID orders by (fork_time_ns DESC, id DESC), so while the newer generation is live it always wins the as-of read and
	// the exited one cannot be selected at all. That selection gap is real but separate from flow attribution, which is what this
	// test pins.
	insertEventsViaIngest(ctx, t, d, host, []api.Event{
		{EventID: "f-716", HostID: host, TimestampNs: now, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":51865,"parent_pid":1,"pidversion":121027}`)},
		{EventID: "e-716-bash", HostID: host, TimestampNs: now + 100*ms, EventType: "exec",
			Payload: json.RawMessage(`{"pid":51865,"ppid":1,"path":"/bin/bash","pidversion":121027}`)},
		{EventID: "x-716", HostID: host, TimestampNs: now + 300*ms, EventType: "exit",
			Payload: json.RawMessage(`{"pid":51865,"exit_code":0}`)},
	})
	insertEventsViaIngest(ctx, t, d, host, []api.Event{
		{EventID: "f-716-b", HostID: host, TimestampNs: now + 400*ms, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":51865,"parent_pid":1,"pidversion":121026}`)},
		{EventID: "e-716-sh", HostID: host, TimestampNs: now + 500*ms, EventType: "exec",
			Payload: json.RawMessage(`{"pid":51865,"ppid":1,"path":"/bin/sh","pidversion":121026}`)},
	})
	// The flow is ingested LAST, in its own batch, well after generation 1's exit ingested. That ordering is the #716 condition:
	// separate batches are exactly why a flow's ingest time lands past its own process's exit ingest time.
	insertEventsViaIngest(ctx, t, d, host, []api.Event{
		{EventID: "nc-716", HostID: host, TimestampNs: now + 150*ms, EventType: "network_connect",
			Payload: json.RawMessage(
				`{"pid":51865,"pidversion":121027,"protocol":"tcp","direction":"outbound","remote_address":"15.204.95.87","remote_port":443}`)},
		{EventID: "dns-716", HostID: host, TimestampNs: now + 160*ms, EventType: "dns_query",
			Payload: json.RawMessage(`{"pid":51865,"pidversion":121027,"query_name":"edr.fleetdm.site","query_type":"A"}`)},
	})

	// Read as of generation 1's exec instant: generation 2 has not forked yet, so the as-of bracket resolves the bash row.
	var owner *api.ProcessDetail
	require.Eventually(t, func() bool {
		p, err := d.Service().GetProcessDetail(ctx, host, pid, now+100*ms, nil)
		if err != nil || p == nil {
			return false
		}
		owner = p
		return len(p.NetworkConnections) == 1 && len(p.DNSQueries) == 1
	}, 10*time.Second, 100*time.Millisecond,
		"the flow and DNS query carrying this generation's pidversion must surface on it despite ingesting after its exit")

	require.NotNil(t, owner)
	assert.Equal(t, "/bin/bash", owner.Process.Path, "resolved the generation the flow belongs to")
	assert.Equal(t, "nc-716", owner.NetworkConnections[0].EventID)
	assert.Equal(t, "dns-716", owner.DNSQueries[0].EventID, "the fix covers dns_query, not only network_connect")

	// The live sibling generation must not claim the flow. Before the fix its open-ended window served it.
	sibling, err := d.Service().GetProcessDetail(ctx, host, pid, now+500*ms, nil)
	require.NoError(t, err)
	require.NotNil(t, sibling)
	assert.Equal(t, "/bin/sh", sibling.Process.Path, "resolved the sibling generation")
	assert.Empty(t, sibling.NetworkConnections, "a flow carrying another generation's pidversion must not appear here")
	assert.Empty(t, sibling.DNSQueries, "same for dns_query")
}

// spec:server-rest-api/per-process-detail-with-re-exec-chain/a-flow-without-a-kernel-generation-is-attributed-by-the-lifetime-window
//
// The legacy arm end to end: a flow carrying no pidversion still surfaces via the lifetime window, so a pre-#403 agent's data does
// not vanish from the panel when identity becomes the primary rule.
func TestProcessDetail_LegacyFlowWithoutPIDVersionStillSurfaces(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	ctx := t.Context()

	const (
		host = "h-716-legacy-detail"
		pid  = 7373
	)
	now := time.Now().UnixNano()
	ms := int64(time.Millisecond)

	insertEventsViaIngest(ctx, t, d, host, []api.Event{
		{EventID: "f-legacy", HostID: host, TimestampNs: now, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":7373,"parent_pid":1}`)},
		{EventID: "e-legacy", HostID: host, TimestampNs: now + 100*ms, EventType: "exec",
			Payload: json.RawMessage(`{"pid":7373,"ppid":1,"path":"/bin/legacy"}`)},
		{EventID: "nc-legacy", HostID: host, TimestampNs: now + 150*ms, EventType: "network_connect",
			Payload: json.RawMessage(`{"pid":7373,"protocol":"tcp","direction":"outbound","remote_address":"1.2.3.4","remote_port":443}`)},
	})

	require.Eventually(t, func() bool {
		p, err := d.Service().GetProcessDetail(ctx, host, pid, now+150*ms, nil)
		return err == nil && p != nil && len(p.NetworkConnections) == 1
	}, 10*time.Second, 100*time.Millisecond, "a flow carrying no pidversion must still surface via the lifetime window")
}

// spec:server-rest-api/per-process-detail-with-re-exec-chain/a-named-generation-of-a-re-exec-chain-is-addressable
// spec:server-rest-api/per-process-detail-with-re-exec-chain/a-pidversion-naming-no-generation-is-not-silently-substituted
//
// Addressing, the other half of #716. Attribution alone leaves the reported symptom in place: a re-exec preserves the chain's
// original fork_time_ns (insertReExec does this deliberately), so both generations tie on it and GetProcessByPID's
// (fork_time_ns DESC, id DESC) ordering always resolves the newest. Measured against the running dev server, asking for the bash
// generation's own exec instant still returned the curl generation, which then correctly reported no flows, so the panel still read
// "No network activity" for the connection an alert fired on. Naming the generation is what makes the owning one reachable.
func TestProcessDetail_PIDVersionAddressesAGenerationTheAsOfReadCannotReach(t *testing.T) {
	t.Parallel()
	d := newDetection(t, detectionOpts{mode: bootstrap.ModeFull})
	ctx := t.Context()

	const (
		host      = "h-716-addressing"
		pid       = 52222
		bashGen   = uint32(151026)
		curlGen   = uint32(151027)
		absentGen = uint32(999999)
	)
	now := time.Now().UnixNano()
	ms := int64(time.Millisecond)
	bashExecNs := now + 100*ms

	// Batch 1: the fork and the bash exec. Waiting for materialisation before sending the re-exec is what makes the chain link
	// deterministically: the builder decides re-exec vs exec-without-fork by whether it can already see the prior generation, and
	// concurrent claim workers give no ordering guarantee across batches (issue #717).
	insertEventsViaIngest(ctx, t, d, host, []api.Event{
		{EventID: "f-addr", HostID: host, TimestampNs: now, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":52222,"parent_pid":1,"pidversion":151025}`)},
		{EventID: "e-addr-bash", HostID: host, TimestampNs: bashExecNs, EventType: "exec",
			Payload: json.RawMessage(`{"pid":52222,"ppid":1,"path":"/bin/bash","pidversion":151026}`)},
	})
	require.Eventually(t, func() bool {
		p, err := d.Service().GetProcessDetail(ctx, host, pid, bashExecNs, nil)
		return err == nil && p != nil && p.Process.Path == "/bin/bash"
	}, 10*time.Second, 100*time.Millisecond, "the bash generation must materialise before the re-exec is sent")

	// The flow belongs to the bash generation.
	insertEventsViaIngest(ctx, t, d, host, []api.Event{
		{EventID: "nc-addr", HostID: host, TimestampNs: now + 150*ms, EventType: "network_connect",
			Payload: json.RawMessage(
				`{"pid":52222,"pidversion":151026,"protocol":"tcp","direction":"outbound","remote_address":"15.204.95.87","remote_port":443}`)},
	})

	// Batch 2: the re-exec into curl. This closes the bash generation and inherits its fork_time_ns.
	insertEventsViaIngest(ctx, t, d, host, []api.Event{
		{EventID: "e-addr-curl", HostID: host, TimestampNs: now + 200*ms, EventType: "exec",
			Payload: json.RawMessage(`{"pid":52222,"ppid":1,"path":"/usr/bin/curl","pidversion":151027}`)},
	})
	require.Eventually(t, func() bool {
		p, err := d.Service().GetProcessDetail(ctx, host, pid, bashExecNs, nil)
		return err == nil && p != nil && p.Process.Path == "/usr/bin/curl"
	}, 10*time.Second, 100*time.Millisecond, "the re-exec must materialise as a second generation on the same pid")

	t.Run("without a pidversion the as-of read cannot reach the older generation", func(t *testing.T) {
		p, err := d.Service().GetProcessDetail(ctx, host, pid, bashExecNs, nil)
		require.NoError(t, err)
		require.NotNil(t, p)
		assert.Equal(t, "/usr/bin/curl", p.Process.Path,
			"the chain ties on fork_time_ns so id DESC wins, even asking for the bash generation's own exec instant")
		assert.Empty(t, p.NetworkConnections, "and the flow correctly does not belong to this generation")
	})

	t.Run("naming the generation reaches it and its flow", func(t *testing.T) {
		gen := bashGen
		p, err := d.Service().GetProcessDetail(ctx, host, pid, bashExecNs, &gen)
		require.NoError(t, err)
		require.NotNil(t, p)
		assert.Equal(t, "/bin/bash", p.Process.Path, "pidversion selects the generation the as-of read could not")
		require.Len(t, p.NetworkConnections, 1, "the named generation carries the flow that belongs to it")
		assert.Equal(t, "nc-addr", p.NetworkConnections[0].EventID)
	})

	t.Run("naming the newest generation still works", func(t *testing.T) {
		gen := curlGen
		p, err := d.Service().GetProcessDetail(ctx, host, pid, bashExecNs, &gen)
		require.NoError(t, err)
		require.NotNil(t, p)
		assert.Equal(t, "/usr/bin/curl", p.Process.Path)
	})

	t.Run("a pidversion no generation carries is not substituted", func(t *testing.T) {
		gen := absentGen
		p, err := d.Service().GetProcessDetail(ctx, host, pid, bashExecNs, &gen)
		require.NoError(t, err)
		assert.Nil(t, p, "must not fall back to another generation; the handler turns this into a 404")
	})
}
