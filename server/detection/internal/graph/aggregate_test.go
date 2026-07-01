package graph

import (
	"testing"

	"github.com/fleetdm/edr/server/detection/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// leaf builds a childless ProcessNode with the identity fields aggregation groups on.
func leaf(id int64, path string, sha string, forkNs int64, exited bool) api.ProcessNode {
	p := api.Process{ID: id, PID: int(id), Path: path, ForkTimeNs: forkNs}
	if sha != "" {
		p.SHA256 = new(sha)
	}
	if exited {
		p.ExitTimeNs = new(forkNs + 1)
	}
	return api.ProcessNode{Process: p}
}

func TestAggregateSiblings_TableCases(t *testing.T) {
	t.Parallel()

	t.Run("N identical-path leaves collapse into one aggregated node with the exited/running split and fork span", func(t *testing.T) {
		t.Parallel()
		in := []api.ProcessNode{
			leaf(1, "/usr/bin/grep", "sha-grep", 100, true),
			leaf(2, "/usr/bin/grep", "sha-grep", 300, true),
			leaf(3, "/usr/bin/grep", "sha-grep", 200, false),
		}
		out := aggregateSiblings(in)
		require.Len(t, out, 1)
		agg := out[0].Aggregated
		require.NotNil(t, agg)
		assert.Equal(t, "/usr/bin/grep", out[0].Path)
		assert.Equal(t, 3, agg.Count)
		assert.Equal(t, 2, agg.ExitedCount)
		assert.Equal(t, 1, agg.RunningCount)
		assert.Equal(t, int64(100), agg.FirstForkNs)
		assert.Equal(t, int64(300), agg.LastForkNs)
		// Representative is the earliest member; its identity is carried on the node.
		assert.Equal(t, int64(1), out[0].ID)
		assert.Nil(t, out[0].Children)
	})

	t.Run("a singleton group stays an individual node (no ×1 badge)", func(t *testing.T) {
		t.Parallel()
		out := aggregateSiblings([]api.ProcessNode{leaf(1, "/bin/ls", "sha-ls", 10, true)})
		require.Len(t, out, 1)
		assert.Nil(t, out[0].Aggregated, "a lone child MUST NOT be aggregated")
	})

	t.Run("same path but different binary identity does not merge", func(t *testing.T) {
		t.Parallel()
		out := aggregateSiblings([]api.ProcessNode{
			leaf(1, "/usr/bin/python3", "sha-A", 10, true),
			leaf(2, "/usr/bin/python3", "sha-B", 20, true),
		})
		require.Len(t, out, 2, "distinct sha256 under one path must stay separate nodes")
		assert.Nil(t, out[0].Aggregated)
		assert.Nil(t, out[1].Aggregated)
	})

	t.Run("a child with its own subtree is never folded away and keeps its descendants", func(t *testing.T) {
		t.Parallel()
		parent := leaf(1, "/bin/bash", "sha-bash", 50, false)
		parent.Children = []api.ProcessNode{
			leaf(10, "/usr/bin/grep", "sha-grep", 60, true),
			leaf(11, "/usr/bin/grep", "sha-grep", 70, true),
		}
		in := []api.ProcessNode{
			parent,
			leaf(2, "/usr/bin/grep", "sha-grep", 80, true),
			leaf(3, "/usr/bin/grep", "sha-grep", 90, true),
		}
		out := aggregateSiblings(in)
		// bash stays individual (non-leaf); the two top-level greps collapse.
		require.Len(t, out, 2)
		var bashNode, aggNode *api.ProcessNode
		for i := range out {
			if out[i].Path == "/bin/bash" {
				bashNode = &out[i]
			} else {
				aggNode = &out[i]
			}
		}
		require.NotNil(t, bashNode)
		require.NotNil(t, aggNode)
		assert.Nil(t, bashNode.Aggregated, "a non-leaf node must not aggregate")
		// bash's own two grep children aggregate one level down.
		require.Len(t, bashNode.Children, 1)
		require.NotNil(t, bashNode.Children[0].Aggregated)
		assert.Equal(t, 2, bashNode.Children[0].Aggregated.Count)
		require.NotNil(t, aggNode.Aggregated)
		assert.Equal(t, 2, aggNode.Aggregated.Count)
	})

	t.Run("output siblings are ordered by first fork time", func(t *testing.T) {
		t.Parallel()
		out := aggregateSiblings([]api.ProcessNode{
			leaf(1, "/bin/z", "z", 300, true),
			leaf(2, "/bin/a", "a", 100, true),
			leaf(3, "/bin/m", "m", 200, true),
		})
		require.Len(t, out, 3)
		assert.Equal(t, int64(100), out[0].ForkTimeNs)
		assert.Equal(t, int64(200), out[1].ForkTimeNs)
		assert.Equal(t, int64(300), out[2].ForkTimeNs)
	})

	t.Run("sample is capped and fork-ordered for a large group", func(t *testing.T) {
		t.Parallel()
		var in []api.ProcessNode
		for i := range int64(1000) {
			id := i + 1
			in = append(in, leaf(id, "/usr/bin/grep", "sha-grep", id, id%2 == 0))
		}
		out := aggregateSiblings(in)
		require.Len(t, out, 1)
		agg := out[0].Aggregated
		require.NotNil(t, agg)
		assert.Equal(t, 1000, agg.Count)
		assert.Len(t, agg.Sample, aggregateSampleCap, "sample MUST be capped")
		assert.Equal(t, int64(1), agg.Sample[0].ForkTimeNs, "sample is fork-ordered, earliest first")
		assert.Equal(t, 500, agg.ExitedCount)
		assert.Equal(t, 500, agg.RunningCount)
	})
}

// aggregationKeyForNode mirrors the grouping key so the PBT can bucket the expected multiset the same way the implementation does.
func aggregationKeyForNode(n api.ProcessNode) string { return aggregationKey(n) }

// spec:server-process-graph-builder/sibling-aggregation-collapses-repeated-leaf-execs/aggregation-preserves-every-leaf-and-its-order
//
// PBT (issue #416): for any random batch of leaf siblings, aggregation preserves the total leaf count (Σ Count over aggregated nodes
// plus one per individual node equals the input size), preserves the per-identity multiset (no child lost, none duplicated, none
// moved to a different group), orders the output by first fork time, and keeps each aggregated node internally consistent
// (exited+running == count, first <= last, sample capped and drawn from the group).
func TestAggregateSiblings_PBT(t *testing.T) {
	t.Parallel()
	paths := []string{"/usr/bin/grep", "/bin/ls", "/usr/bin/docker", "/usr/bin/python3"}
	shas := []string{"", "sha-A", "sha-B"}

	rapid.Check(t, func(rt *rapid.T) {
		n := rapid.IntRange(0, 60).Draw(rt, "n")
		in := make([]api.ProcessNode, 0, n)
		expectedByKey := make(map[string]int)
		inputIDs := make(map[int64]bool)
		for i := range n {
			id := int64(i + 1) // unique, non-zero
			path := rapid.SampledFrom(paths).Draw(rt, "path")
			sha := rapid.SampledFrom(shas).Draw(rt, "sha")
			forkNs := rapid.Int64Range(1, 500).Draw(rt, "fork")
			exited := rapid.Bool().Draw(rt, "exited")
			node := leaf(id, path, sha, forkNs, exited)
			in = append(in, node)
			expectedByKey[aggregationKeyForNode(node)]++
			inputIDs[id] = true
		}

		out := aggregateSiblings(in)

		// Leaf-count preservation + per-identity multiset preservation.
		totalLeaves := 0
		actualByKey := make(map[string]int)
		seenIDs := make(map[int64]bool)
		var prevFork int64 = -1
		for _, node := range out {
			// Ordering: non-decreasing by first fork time.
			assert.GreaterOrEqual(t, nodeFirstForkNs(node), prevFork, "output MUST be ordered by first fork time")
			prevFork = nodeFirstForkNs(node)

			if node.Aggregated == nil {
				totalLeaves++
				actualByKey[aggregationKeyForNode(node)]++
				assert.False(t, seenIDs[node.ID], "an id must not appear twice")
				seenIDs[node.ID] = true
				assert.True(t, inputIDs[node.ID], "every individual node id must be a real input id")
				continue
			}
			agg := node.Aggregated
			require.GreaterOrEqual(t, agg.Count, aggregateMinGroup, "a collapsed group must have >= aggregateMinGroup members")
			totalLeaves += agg.Count
			actualByKey[aggregationKeyForNode(node)] += agg.Count
			// Internal consistency.
			assert.Equal(t, agg.Count, agg.ExitedCount+agg.RunningCount, "exited + running == count")
			assert.LessOrEqual(t, agg.FirstForkNs, agg.LastForkNs)
			assert.Len(t, agg.Sample, min(agg.Count, aggregateSampleCap))
			// The representative's identity matches the group's key, and samples all share it.
			key := aggregationKeyForNode(node)
			for _, s := range agg.Sample {
				assert.Equal(t, key, aggregationKeyForNode(s), "sample members must share the group identity")
				assert.False(t, seenIDs[s.ID], "a sampled id must not collide with another node's id")
				seenIDs[s.ID] = true
				assert.True(t, inputIDs[s.ID], "every sampled id must be a real input id")
			}
		}

		assert.Equal(t, n, totalLeaves, "aggregation must neither drop nor duplicate a leaf")
		assert.Equal(t, expectedByKey, actualByKey, "per-identity multiset must be preserved")
	})
}
