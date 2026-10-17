//go:build integration

// An AI agent's own processes (issue #1361): what the agent ran for itself, with no session marker, as the RSA rerun on edr-dev
// showed Claude Code doing around a session's tool calls.

package tests

import (
	"encoding/json"
	"math"
	"slices"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/detection/internal/graph"
)

// spec:server-rest-api/agent-own-processes/a-session-read-lists-the-agent-s-own-processes-under-it
func TestAgentOwnProcesses(t *testing.T) {
	t.Parallel()
	store, db := openProcessStore(t)
	ctx := t.Context()
	host := "agent-own-" + t.Name()
	const session, forked = "4f491260-0000-4000-8000-000000001361", "3fa5d706-0000-4000-8000-000000001361"
	evt := func(id, typ string, ms int64, payload string) api.Event {
		return api.Event{EventID: id, HostID: host, TimestampNs: at(float64(ms) / 1000), IngestedAtNs: at(float64(ms)/1000) + 1, EventType: typ,
			Payload: json.RawMessage(payload)}
	}
	// proc is a fork and exec of path under ppid, carrying a session's markers when marked names one. A fork names its creator by pid
	// and generation, as the extension sends it; here a process's fork generation is its pid and its exec's the next.
	proc := func(id string, pid, ppid int, ms int64, path, marked string) []api.Event {
		p, pp := strconv.Itoa(pid), strconv.Itoa(ppid)
		forkGen, execGen, parentGen := strconv.Itoa(pid*10), strconv.Itoa(pid*10+1), strconv.Itoa(ppid*10+1)
		env := ""
		if marked != "" {
			env = `,"env":{"CLAUDE_CODE_SESSION_ID":"` + marked + `","CLAUDE_PID":"3036","AI_AGENT":"claude-code_2-1-302_agent"}`
		}
		return []api.Event{
			evt(id+"-f", "fork", ms, `{"child_pid":`+p+`,"parent_pid":`+pp+`,"pidversion":`+forkGen+`,"parent_pidversion":`+parentGen+`}`),
			evt(id+"-x", "exec", ms+1, `{"pid":`+p+`,"ppid":`+pp+`,"pidversion":`+execGen+`,"path":"`+path+`","args":["`+path+`"],`+
				`"cwd":"/Users/v/proj","uid":501,"gid":20`+env+`}`),
		}
	}
	var events []api.Event
	for _, p := range [][]api.Event{
		proc("agent", 3036, 900, 1000, "/Users/v/.local/bin/claude", ""),
		// The agent's own: a plugin scan, and a shell snapshot with its child.
		proc("rg", 3040, 3036, 1100, "/opt/homebrew/bin/rg", ""),
		proc("snap", 3041, 3036, 1200, "/bin/zsh", ""),
		proc("snap-child", 3042, 3041, 1210, "/usr/bin/env", ""),
		// The session's tool call and what it started: the session's, not the agent's own.
		proc("tool", 3050, 3036, 1300, "/bin/zsh", session),
		proc("tool-child", 3051, 3050, 1310, "/usr/bin/curl", ""),
		// The /fork daemon and its spare are the agent's own; the forked session's process under the spare is that session's.
		proc("daemon", 3060, 3036, 1400, "/Users/v/.local/bin/claude", ""),
		proc("spare", 3061, 3060, 1410, "/Users/v/.local/share/claude/versions/2.1.302", ""),
		proc("fork-tool", 3062, 3061, 1420, "/bin/zsh", forked),
		// After the window: another session's time, when the agent served it.
		proc("late", 3070, 3036, 5000, "/opt/homebrew/bin/rg", ""),
	} {
		events = append(events, p...)
	}
	require.NoError(t, graph.NewBuilder(store, discardLogger()).ProcessBatch(ctx, events))
	var agentID int64
	require.NoError(t, db.GetContext(ctx, &agentID, "SELECT id FROM processes WHERE host_id = ? AND pid = 3036", host))

	names := func(nodes []api.ProcessNode) map[int][]int {
		tree := map[int][]int{}
		var walk func(parent int, nodes []api.ProcessNode)
		walk = func(parent int, nodes []api.ProcessNode) {
			for _, n := range nodes {
				tree[parent] = append(tree[parent], n.PID)
				walk(n.PID, n.Children)
			}
		}
		walk(3036, nodes)
		for _, children := range tree {
			slices.Sort(children)
		}
		return tree
	}
	own, cut, err := graph.NewQuery(store).BuildAgentOwnTree(ctx, host, agentID, 0, at(4.0))
	require.NoError(t, err)
	assert.False(t, cut)
	assert.Equal(t, map[int][]int{3036: {3040, 3041, 3060}, 3041: {3042}, 3060: {3061}}, names(own),
		"the agent's scans, snapshot and fork daemon, nested by creator; not the session's tool call or the forked session's process")

	all, _, err := graph.NewQuery(store).BuildAgentOwnTree(ctx, host, agentID, 0, math.MaxInt64)
	require.NoError(t, err)
	assert.Contains(t, names(all)[3036], 3070, "unbounded, the agent's whole life")

	// spec:server-rest-api/agent-own-processes/an-agent-s-own-processes-alerts-are-read-by-the-agent
	t.Run("the alerts on the agent's own processes", func(t *testing.T) {
		rowOf := func(pid int) int64 {
			var id int64
			require.NoError(t, db.GetContext(ctx, &id, "SELECT id FROM processes WHERE host_id = ? AND pid = ? ORDER BY id DESC LIMIT 1", host, pid))
			return id
		}
		alerted := map[int64]int{}
		for _, pid := range []int{3040, 3042, 3050, 3070} {
			id, _, err := store.InsertAlert(ctx, api.Alert{HostID: host, RuleID: "r" + strconv.Itoa(pid), Source: api.AlertSourceDetection,
				Severity: api.SeverityHigh, Title: "t", Description: "d", ProcessID: rowOf(pid), Subject: strconv.Itoa(pid)}, nil)
			require.NoError(t, err)
			alerted[id] = pid
		}
		read := func(fromNs, toNs int64) []int {
			got, err := store.ListAlerts(ctx, api.AlertFilter{HostID: host, AgentProcessID: agentID, AgentFromNs: fromNs, AgentToNs: toNs,
				Limit: 10})
			require.NoError(t, err)
			var pids []int
			for _, a := range got {
				pids = append(pids, alerted[a.ID])
			}
			return pids
		}
		assert.ElementsMatch(t, []int{3040, 3042}, read(0, at(4.0)),
			"the scan and the snapshot's child in the window; not the session's tool call or the scan after it")
		assert.ElementsMatch(t, []int{3040, 3042, 3070}, read(0, math.MaxInt64), "the agent's whole life, when it served only this session")
		assert.ElementsMatch(t, []int{3042}, read(at(1.15), at(4.0)), "a window starting after the scan, as a later session's would")
	})
}
