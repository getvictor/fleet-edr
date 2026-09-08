package sigmabind_test

import (
	"encoding/json"
	"testing"

	"pgregory.net/rapid"

	rulesapi "github.com/fleetdm/edr/server/rules/api"
	"github.com/fleetdm/edr/server/rules/internal/sigmabind"
)

// The round trip for the file_rename wire struct: whatever two paths a rename carries, the decode surfaces them under their
// Sigma names, unchanged and not swapped.
//
// Property-based rather than table-driven because the input space that matters here is string content, and the interesting
// inputs are the ones nobody writes in a table: a path containing a quote, a backslash, a newline, a non-ASCII byte, the empty
// string. A rename's two fields are structurally identical, so a swap or a shared-buffer aliasing bug is invisible to any test
// whose two paths look alike; the generator draws them independently so most cases distinguish them.
//
// This guards the join the whole detection rests on. TargetFilename is what the rule's condition matches, and reporting the
// SOURCE there would fire on an attacker's scratch path while ignoring the sudoers file that actually became policy.
func TestFileRenamePayloadRoundTrips(t *testing.T) {
	t.Parallel()

	// A vocabulary reaching the shapes that break naive encoders, plus free-form draws for everything else.
	awkward := []string{
		"", "/", "/etc/sudoers", `/tmp/a"b`, `/tmp/a\b`, "/tmp/a\nb", "/tmp/ünïcodé", "/tmp/  spaces  ",
		"/private/etc/sudoers.d/evil", "/tmp/" + string(rune(0x7f)),
	}
	rapid.Check(t, func(rt *rapid.T) {
		draw := func(label string) string {
			if rapid.Bool().Draw(rt, label+"-awkward") {
				return rapid.SampledFrom(awkward).Draw(rt, label+"-vocab")
			}
			return rapid.String().Draw(rt, label)
		}
		source := draw("source")
		target := draw("target")
		pid := rapid.IntRange(0, 1<<22).Draw(rt, "pid")

		payload, err := json.Marshal(map[string]any{"pid": pid, "source_path": source, "path": target})
		if err != nil {
			rt.Fatalf("marshal: %v", err)
		}
		ev, err := sigmabind.NewOpenEventLazy(
			rulesapi.Event{EventID: "e", EventType: "file_rename", Payload: payload},
			func() (string, error) { return "/bin/mv", nil })
		if err != nil {
			rt.Fatalf("decode: %v", err)
		}

		// An EMPTY path is absent rather than empty, which is presentString's convention across every field this package
		// supplies: a rule asking for a field it was not given must get "no value", not a value that happens to be "". The
		// property found this on its first run, which a literal fixture would never have reached. A rename with an empty
		// path is malformed anyway (both are required on the wire), so declining to supply it is the right answer.
		assertField(rt, ev, "TargetFilename", target)
		assertField(rt, ev, "SourceFilename", source)
	})
}

// assertField encodes the supplied-versus-absent contract once, so both fields are held to the same rule and neither can drift
// into a special case.
func assertField(rt *rapid.T, ev *sigmabind.Event, name, want string) {
	rt.Helper()
	got, ok := ev.Field(name)
	if want == "" {
		if ok {
			rt.Fatalf("%s = %v, want absent: an empty path is not a value a rule should match on", name, got)
		}
		return
	}
	if !ok || len(got) != 1 || got[0] != want {
		rt.Fatalf("%s = %v (ok=%v), want [%q]", name, got, ok, want)
	}
}
