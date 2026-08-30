package sigmabind

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/rules/api"
)

// execEvent builds an exec event from a path and argv, so these tests go through the real adapter rather than calling the
// extractors directly. What matters is what a rule sees, and that is the field, not the helper.
func execEvent(t *testing.T, path string, argv ...string) *Event {
	t.Helper()
	payload, err := json.Marshal(map[string]any{"pid": 1, "ppid": 0, "path": path, "args": argv})
	require.NoError(t, err)
	e, err := NewEvent(api.Event{EventID: "e1", EventType: "exec", Payload: payload})
	require.NoError(t, err)
	return e
}

func field(t *testing.T, e *Event, name string) []string {
	t.Helper()
	v, _ := e.Field(name)
	return v
}

// spec:server-detection-rules-engine/argument-position-is-available-as-a-field/a-rule-matches-the-verb-rather-than-the-whole-command-line
//
// TestSubcommand covers the field that makes the keychain and launch-agent rules expressible. The negative cases carry the weight:
// a field that merely found the flagged token anywhere in argv would satisfy every positive case here and still be the over-matching
// behaviour this exists to avoid.
func TestSubcommand(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		argv []string
		want []string
	}{
		{"the first non-flag token after argv[0]", []string{"security", "dump-keychain"}, []string{"dump-keychain"}},
		{"flags before it are skipped", []string{"security", "-v", "dump-keychain"}, []string{"dump-keychain"}},
		{"several flags are skipped", []string{"security", "-v", "-q", "dump-keychain"}, []string{"dump-keychain"}},
		// The case the naive CommandLine conversion gets wrong: `security` acts on `help` and never reads a keychain.
		{"the FIRST non-flag token decides", []string{"security", "help", "dump-keychain"}, []string{"help"}},
		{"a later occurrence does not win", []string{"launchctl", "print", "load"}, []string{"print"}},
		{"argv[0] is not a subcommand", []string{"dump-keychain"}, nil},
		{"no subcommand at all", []string{"security"}, nil},
		{"only flags", []string{"security", "-v", "-q"}, nil},
		// Empty counts as the verb rather than being skipped: the tool would reject it and never act on the later token.
		{"an empty token is the subcommand, so nothing later is", []string{"security", "", "dump-keychain"}, nil},
		{"empty argv", nil, nil},
		{"a path operand can be the subcommand if it comes first", []string{"launchctl", "/tmp/x", "load"}, []string{"/tmp/x"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, field(t, execEvent(t, "/usr/bin/security", tc.argv...), "Subcommand"))
		})
	}
}

// spec:server-detection-rules-engine/argument-position-is-available-as-a-field/an-operand-after-the-verb-is-matchable
//
// TestCommandArguments covers the operands after the subcommand, which is how the launch-agent rule asks "is one of the later
// arguments a plist path" without conflating it with the subcommand itself.
func TestCommandArguments(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		argv []string
		want []string
	}{
		{"operands after the subcommand", []string{"launchctl", "load", "/Library/LaunchAgents/x.plist"},
			[]string{"/Library/LaunchAgents/x.plist"}},
		{"flags among the operands are skipped", []string{"launchctl", "load", "-w", "/Library/LaunchAgents/x.plist"},
			[]string{"/Library/LaunchAgents/x.plist"}},
		{"several operands", []string{"launchctl", "bootstrap", "gui/501", "/tmp/a.plist"}, []string{"gui/501", "/tmp/a.plist"}},
		{"the subcommand itself is not an operand", []string{"launchctl", "load"}, nil},
		{"empty operands are dropped", []string{"launchctl", "load", "", "/tmp/a.plist"}, []string{"/tmp/a.plist"}},
		{"no subcommand means no operands", []string{"launchctl"}, nil},
		{"flags before the subcommand do not count as it", []string{"launchctl", "-v", "load", "/tmp/a.plist"}, []string{"/tmp/a.plist"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, field(t, execEvent(t, "/bin/launchctl", tc.argv...), "CommandArguments"))
		})
	}
}

// spec:server-detection-rules-engine/argument-position-is-available-as-a-field/a-leading-assignment-is-distinguished-from-a-later-argument
//
// TestEnvAssignments covers the window that distinguishes an injection from an ordinary argument. Both orderings below produce an
// identical CommandLine, and only one is an injection, which is the reason this field exists at all.
func TestEnvAssignments(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		path string
		argv []string
		want []string
	}{
		{"shell form: the assignment is argv[0]", "/usr/bin/true",
			[]string{"DYLD_INSERT_LIBRARIES=/tmp/e.dylib", "/usr/bin/true"}, []string{"DYLD_INSERT_LIBRARIES=/tmp/e.dylib"}},
		{"the same text as a later argument is NOT an assignment", "/usr/bin/true",
			[]string{"/usr/bin/true", "DYLD_INSERT_LIBRARIES=/tmp/e.dylib"}, nil},
		{"env form: leading assignments", "/usr/bin/env",
			[]string{"env", "DYLD_INSERT_LIBRARIES=/tmp/e.dylib", "/usr/bin/true"}, []string{"DYLD_INSERT_LIBRARIES=/tmp/e.dylib"}},
		{"env form: several leading assignments", "/usr/bin/env",
			[]string{"env", "A=1", "B=2", "prog"}, []string{"A=1", "B=2"}},
		{"env form: the window ends at the first non-assignment", "/usr/bin/env",
			[]string{"env", "A=1", "prog", "C=3"}, []string{"A=1"}},
		{"a shim path ending in /env counts as env", "/opt/homebrew/bin/env",
			[]string{"env", "A=1", "prog"}, []string{"A=1"}},
		{"a non-env binary gets only argv[0]", "/bin/sh",
			[]string{"sh", "A=1", "B=2"}, nil},
		{"no assignments", "/usr/bin/true", []string{"/usr/bin/true"}, nil},
		{"empty argv", "/usr/bin/env", nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, field(t, execEvent(t, tc.path, tc.argv...), "EnvAssignments"))
		})
	}
}

// TestComputedFieldsAreAbsentWhenEmpty pins that a computed field with nothing to report is ABSENT rather than present and empty,
// which is what keeps `Field: null` meaning what its author intended and matches how Image and CommandLine already behave.
func TestComputedFieldsAreAbsentWhenEmpty(t *testing.T) {
	t.Parallel()

	e := execEvent(t, "/usr/bin/true", "/usr/bin/true")
	for _, name := range []string{"Subcommand", "CommandArguments", "EnvAssignments"} {
		values, present := e.Field(name)
		assert.False(t, present, "%s must be absent", name)
		assert.Nil(t, values)
	}
}
