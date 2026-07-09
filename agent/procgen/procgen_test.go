package procgen

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"pgregory.net/rapid"
)

// execBytes / forkBytes / exitBytes build the same raw JSON the extension delivers, so tests drive the real ObserveEventBytes parse path
// rather than poking the map through internals. json.Marshal of these fixed maps cannot fail, so the error is ignored.
func execBytes(pid int, pidversion uint32) []byte {
	b, _ := json.Marshal(map[string]any{"event_type": "exec", "payload": map[string]any{"pid": pid, "pidversion": pidversion}})
	return b
}

func forkBytes(childPID int, pidversion uint32) []byte {
	b, _ := json.Marshal(map[string]any{"event_type": "fork", "payload": map[string]any{"child_pid": childPID, "pidversion": pidversion}})
	return b
}

func exitBytes(pid int) []byte {
	b, _ := json.Marshal(map[string]any{"event_type": "exit", "payload": map[string]any{"pid": pid, "exit_code": 0}})
	return b
}

func TestRegistry_Check(t *testing.T) {
	t.Parallel()
	t.Run("exec records the generation and matches it", func(t *testing.T) {
		t.Parallel()
		r := NewRegistry()
		r.ObserveEventBytes(execBytes(100, 7))
		assert.Equal(t, VerdictMatch, r.Check(100, 7))
	})

	t.Run("a different generation is a mismatch", func(t *testing.T) {
		t.Parallel()
		r := NewRegistry()
		r.ObserveEventBytes(execBytes(100, 7))
		assert.Equal(t, VerdictMismatch, r.Check(100, 6))
	})

	t.Run("an untracked pid is unknown", func(t *testing.T) {
		t.Parallel()
		r := NewRegistry()
		assert.Equal(t, VerdictUnknown, r.Check(100, 7))
	})

	t.Run("fork records the child's generation", func(t *testing.T) {
		t.Parallel()
		r := NewRegistry()
		r.ObserveEventBytes(forkBytes(200, 3))
		assert.Equal(t, VerdictMatch, r.Check(200, 3))
	})

	t.Run("a re-exec on the same pid overwrites the generation", func(t *testing.T) {
		t.Parallel()
		r := NewRegistry()
		r.ObserveEventBytes(execBytes(100, 7))
		r.ObserveEventBytes(execBytes(100, 8)) // re-exec increments the kernel pidversion
		assert.Equal(t, VerdictMismatch, r.Check(100, 7), "the stale generation no longer matches")
		assert.Equal(t, VerdictMatch, r.Check(100, 8), "the current generation matches")
	})

	t.Run("exit clears the pid so a later check is unknown (falls back)", func(t *testing.T) {
		t.Parallel()
		r := NewRegistry()
		r.ObserveEventBytes(execBytes(100, 7))
		r.ObserveEventBytes(exitBytes(100))
		assert.Equal(t, VerdictUnknown, r.Check(100, 7))
		assert.Equal(t, 0, r.Len())
	})

	t.Run("an exec without a pidversion is ignored (boot snapshot / legacy agent)", func(t *testing.T) {
		t.Parallel()
		r := NewRegistry()
		r.ObserveEventBytes([]byte(`{"event_type":"exec","payload":{"pid":100}}`))
		assert.Equal(t, VerdictUnknown, r.Check(100, 0))
		assert.Equal(t, 0, r.Len())
	})

	t.Run("non-process events and malformed JSON never track a pid or panic", func(t *testing.T) {
		t.Parallel()
		r := NewRegistry()
		r.ObserveEventBytes([]byte(`{"event_type":"network_connect","payload":{"pid":100,"pidversion":7}}`))
		r.ObserveEventBytes([]byte(`{not json`))
		r.ObserveEventBytes(nil)
		assert.Equal(t, 0, r.Len())
	})

	t.Run("a nil registry reports unknown rather than panicking", func(t *testing.T) {
		t.Parallel()
		var r *Registry
		assert.Equal(t, VerdictUnknown, r.Check(100, 7))
	})
}

// TestRegistry_ObserveMatchesModel is a property-based check that Check always agrees with a plain model of the last event seen per pid:
// the current generation is the last exec/fork-with-pidversion, cleared by a later exit. This covers arbitrary interleavings the table
// above cannot enumerate (issue #627; the state-machine-transition PBT shape from the testing strategy).
func TestRegistry_ObserveMatchesModel(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		r := NewRegistry()
		model := map[int]uint32{} // pid -> current generation; absence means untracked
		pidGen := rapid.IntRange(1, 5)
		verGen := rapid.Uint32Range(1, 4)
		n := rapid.IntRange(0, 40).Draw(t, "steps")
		for range n {
			pid := pidGen.Draw(t, "pid")
			switch rapid.SampledFrom([]string{"exec", "fork", "exit"}).Draw(t, "kind") {
			case "exec":
				v := verGen.Draw(t, "v")
				r.ObserveEventBytes(execBytes(pid, v))
				model[pid] = v
			case "fork":
				v := verGen.Draw(t, "v")
				r.ObserveEventBytes(forkBytes(pid, v))
				model[pid] = v
			case "exit":
				r.ObserveEventBytes(exitBytes(pid))
				delete(model, pid)
			}
		}
		for pid := 1; pid <= 5; pid++ {
			for v := uint32(1); v <= 4; v++ {
				want := VerdictUnknown
				if cur, ok := model[pid]; ok {
					if cur == v {
						want = VerdictMatch
					} else {
						want = VerdictMismatch
					}
				}
				assert.Equalf(t, want, r.Check(pid, v), "pid=%d v=%d", pid, v)
			}
		}
	})
}
