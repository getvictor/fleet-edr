package sigmabind

import (
	"encoding/json"
	"errors"
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
// spec:server-detection-rules-engine/argument-position-is-available-as-a-field/an-option-before-an-assignment-does-not-hide-it
// spec:server-detection-rules-engine/argument-position-is-available-as-a-field/an-option-s-operand-is-not-an-assignment
// spec:server-detection-rules-engine/argument-position-is-available-as-a-field/an-assignment-after-the-end-of-options-marker-belongs-to-the-command
// spec:server-detection-rules-engine/argument-position-is-available-as-a-field/a-name-a-shell-would-reject-does-not-end-the-run
// spec:server-detection-rules-engine/argument-position-is-available-as-a-field/an-attached-operand-is-not-read-as-further-options
// spec:server-detection-rules-engine/argument-position-is-available-as-a-field/an-invocation-env-would-refuse-reports-no-assignments
// spec:server-detection-rules-engine/argument-position-is-available-as-a-field/an-option-suppressing-the-command-reports-no-assignments
// spec:server-detection-rules-engine/argument-position-is-available-as-a-field/a-command-line-carried-as-an-option-value-reports-no-assignments
//
// TestEnvAssignments covers the window that distinguishes an injection from an ordinary argument. The two orderings below join to
// different CommandLine strings but carry the same assignment text, so a `CommandLine|contains` match cannot tell them apart, and
// only one of them is an injection. That is the reason this field exists.
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

		// Issue #792: env's own options used to end the scan, so every assignment behind one was invisible. The first row is a
		// real injection shape that this field reported nothing for.
		{"env -i hides nothing now", "/usr/bin/env",
			[]string{"env", "-i", "DYLD_INSERT_LIBRARIES=/tmp/e.dylib", "/bin/true"},
			[]string{"DYLD_INSERT_LIBRARIES=/tmp/e.dylib"}},
		{"a lone dash is the historic synonym for the ignore-environment option", "/usr/bin/env",
			[]string{"env", "-", "A=1", "prog"}, []string{"A=1"}},
		{"an option's operand is not mistaken for an assignment", "/usr/bin/env",
			[]string{"env", "-u", "PATH", "A=1", "prog"}, []string{"A=1"}},
		{"an unset of the very variable being looked for is not an injection", "/usr/bin/env",
			[]string{"env", "-u", "DYLD_INSERT_LIBRARIES", "/bin/true"}, nil},
		{"an attached operand consumes nothing extra", "/usr/bin/env",
			[]string{"env", "-uPATH", "A=1", "prog"}, []string{"A=1"}},
		{"a cluster's operand belongs to its last letter", "/usr/bin/env",
			[]string{"env", "-iu", "PATH", "A=1", "prog"}, []string{"A=1"}},
		{"options with no operand", "/usr/bin/env",
			[]string{"env", "-i", "-v", "A=1", "prog"}, []string{"A=1"}},
		{"the NUL-output option means no command ran", "/usr/bin/env",
			// Measured: `env -0 A=1 /bin/sh` exits `cannot specify command with -0`. Review caught this being modelled as an
			// ordinary no-operand option, which reported an assignment for an invocation that execs nothing.
			[]string{"env", "-0", "DYLD_INSERT_LIBRARIES=/tmp/e.dylib", "/bin/true"}, nil},
		{"the NUL-output option inside a cluster too", "/usr/bin/env",
			[]string{"env", "-i0", "DYLD_INSERT_LIBRARIES=/tmp/e.dylib", "/bin/true"}, nil},
		{"everything after the end-of-options marker is operands", "/usr/bin/env",
			[]string{"env", "--", "A=1", "prog"}, []string{"A=1"}},
		{"after the end-of-options marker an option-looking token is the command", "/usr/bin/env",
			// `env -- -i A=1` runs a command NAMED -i with A=1 as its argument, so there is no assignment. Without honouring
			// `--` this parses -i as an option and reports A=1 as an injection that never happened.
			[]string{"env", "--", "-i", "A=1"}, nil},
		{"a token a shell would reject does not end the run", "/usr/bin/env",
			// Measured against env(1) on macOS: `env 2+2=4 MARKER=yes sh -c 'echo $MARKER'` prints yes, so env really does
			// apply both and keep going. An earlier round ended the run here instead, on the theory that only a shell-legal
			// name counts, and that was a bypass: `env 2+2=4 DYLD_INSERT_LIBRARIES=x prog` reported nothing at all.
			[]string{"env", "2+2=4", "DYLD_INSERT_LIBRARIES=/tmp/e.dylib", "prog"},
			[]string{"DYLD_INSERT_LIBRARIES=/tmp/e.dylib"}},
		{"a token assigning nothing is the command and ends the run", "/usr/bin/env",
			[]string{"env", "A=1", "prog", "B=2"}, []string{"A=1"}},
		{"a malformed name is not reported, but what follows it still is", "/usr/bin/env",
			// `=bad` is skipped by the report filter rather than by the boundary, so B=2 behind it survives.
			[]string{"env", "A=1", "=bad", "B=2"}, []string{"A=1", "B=2"}},

		// The two rows below are the option-parse bypasses review found in the first cut of this fix, both verified against
		// env(1) rather than reasoned about.
		{"an attached operand ending in an option letter consumes nothing extra", "/usr/bin/env",
			// `env -uS A=1 prog` unsets S and applies A=1: measured. Reading the LAST letter of the cluster to decide whether
			// the next argument is an operand ate A=1 here, and would equally have eaten a DYLD_ assignment.
			[]string{"env", "-uS", "DYLD_INSERT_LIBRARIES=/tmp/e.dylib", "prog"},
			[]string{"DYLD_INSERT_LIBRARIES=/tmp/e.dylib"}},
		{"an option env does not have means nothing ran", "/usr/bin/env",
			// `env -z A=1 prog` exits with `illegal option -- z` and never execs prog, so reporting the assignment would be a
			// finding for an injection that did not happen.
			[]string{"env", "-z", "DYLD_INSERT_LIBRARIES=/tmp/e.dylib", "/bin/true"}, nil},
		{"an unknown option inside an otherwise valid cluster also refuses", "/usr/bin/env",
			[]string{"env", "-iz", "A=1", "prog"}, nil},
		{"an unknown option carrying an equals sign refuses too", "/usr/bin/env",
			// This row is the one that makes the refusal observable, and mutation testing is what found that out. On a refused
			// option the scan is reported as starting at the offending token, which normally ends the run by itself for want of
			// an equals sign; `-z=1` has one, so without the refusal the run would step over it and collect what followed.
			// Measured: env exits `illegal option -- z` here and execs nothing.
			[]string{"env", "-z=1", "DYLD_INSERT_LIBRARIES=/tmp/e.dylib", "prog"}, nil},
		{"an operand-taking option's own operand may look like an option", "/usr/bin/env",
			// -P's operand is a path, and a path is not parsed as a further option.
			[]string{"env", "-P", "-weird", "A=1", "prog"}, []string{"A=1"}},
		{"the string option's payload is not parsed for assignments", "/usr/bin/env",
			// KNOWN GAP, pinned deliberately: `-S` carries a whole command line that env re-splits, so an assignment inside it
			// is invisible to this field. Reporting nothing is the safe direction (a miss, not a fabricated finding); splitting
			// -S the way env does is tracked separately.
			[]string{"env", "-S", "DYLD_INSERT_LIBRARIES=/tmp/e.dylib prog"}, nil},
		{"nothing after the string option is an assignment either", "/usr/bin/env",
			// Measured: `env -S "/bin/echo hi" DYLD_INSERT_LIBRARIES=/tmp/x` prints `hi DYLD_INSERT_LIBRARIES=/tmp/x`, so the
			// trailing token is echo's ARGUMENT. Skipping only the payload and collecting what followed fabricated an injection
			// finding, which review caught.
			[]string{"env", "-S", "/bin/echo hi", "DYLD_INSERT_LIBRARIES=/tmp/x"}, nil},
		{"an attached string-option payload ends the run too", "/usr/bin/env",
			[]string{"env", "-S/bin/echo hi", "DYLD_INSERT_LIBRARIES=/tmp/x"}, nil},
		{"an option with a missing operand at the end of argv", "/usr/bin/env",
			[]string{"env", "-u"}, nil},
		{"options with no command at all", "/usr/bin/env",
			[]string{"env", "-i"}, nil},
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

// TestEnvAssignments_RejectsNonAssignments pins that merely containing "=" is not enough to be REPORTED. `=VALUE` and `2+2=4` are
// not well-formed assignments, and admitting them would let a future rule match on something no shell would have assigned.
//
// The distinction this test does not make, and TestEnvAssignments does: rejecting a token from the report is not the same as
// ending the scan at it. env keeps applying assignments past a name a shell would reject, so the boundary stays permissive and
// only the reported set is narrowed. Getting those two the same way round was a measured bypass.
func TestEnvAssignments_RejectsNonAssignments(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		argv []string
		want []string
	}{
		{"a missing key is not an assignment", []string{"=VALUE"}, nil},
		{"an expression is not an assignment", []string{"2+2=4"}, nil},
		{"a key may not start with a digit", []string{"1A=x"}, nil},
		{"a key may not contain a dash", []string{"A-B=x"}, nil},
		{"underscores and digits are fine after the first character", []string{"_A1_B=x"}, []string{"_A1_B=x"}},
		{"a real assignment survives", []string{"DYLD_INSERT_LIBRARIES=/tmp/x"}, []string{"DYLD_INSERT_LIBRARIES=/tmp/x"}},
		{"an empty value is still an assignment", []string{"A="}, []string{"A="}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, field(t, execEvent(t, "/usr/bin/true", tc.argv...), "EnvAssignments"))
		})
	}
}

// spec:server-detection-rules-engine/a-rule-can-match-on-the-parent-process/the-parent-image-is-supplied-by-the-caller
//
// TestParentImage covers the one field this package does not read from the payload. An exec event carries ppid, not the parent's
// path, and this package deliberately does not know the process graph, so the caller resolves it and passes it in.
func TestParentImage(t *testing.T) {
	t.Parallel()

	payload := []byte(`{"pid":1,"ppid":2,"path":"/bin/bash","args":["bash"]}`)

	t.Run("supplied by the caller", func(t *testing.T) {
		t.Parallel()
		e, err := NewExecEvent(api.Event{EventID: "e1", EventType: "exec", Payload: payload}, "/Applications/X.app/Contents/MacOS/X")
		require.NoError(t, err)
		values, present := e.Field("ParentImage")
		assert.True(t, present)
		assert.Equal(t, []string{"/Applications/X.app/Contents/MacOS/X"}, values)
	})

	t.Run("an unresolved parent is absent, not empty", func(t *testing.T) {
		t.Parallel()
		// The honest answer when the graph could not resolve the parent: a rule keyed on it declines rather than matching a
		// process whose image we do not know.
		e, err := NewExecEvent(api.Event{EventID: "e1", EventType: "exec", Payload: payload}, "")
		require.NoError(t, err)
		_, present := e.Field("ParentImage")
		assert.False(t, present)
	})

	t.Run("NewEvent supplies no parent at all", func(t *testing.T) {
		t.Parallel()
		// A caller that has not resolved a parent gets a field that is absent rather than wrong.
		e, err := NewEvent(api.Event{EventID: "e1", EventType: "exec", Payload: payload})
		require.NoError(t, err)
		_, present := e.Field("ParentImage")
		assert.False(t, present)
	})

	t.Run("a malformed payload still errors", func(t *testing.T) {
		t.Parallel()
		_, err := NewExecEvent(api.Event{EventID: "e1", EventType: "exec", Payload: []byte(`{"path":123}`)}, "/bin/sh")
		require.Error(t, err)
	})
}

// TestParentImageLazy covers the deferred resolver: that it is not called until the field is read, runs at most once, and reports a
// failure rather than presenting it as an absent parent.
func TestParentImageLazy(t *testing.T) {
	t.Parallel()

	payload := []byte(`{"pid":1,"ppid":2,"path":"/bin/bash","args":["bash"]}`)
	event := func() api.Event { return api.Event{EventID: "e1", EventType: "exec", Payload: payload} }

	t.Run("not called until the field is read", func(t *testing.T) {
		t.Parallel()
		calls := 0
		e, err := NewExecEventLazy(event(), func() (string, error) { calls++; return "/Applications/X", nil })
		require.NoError(t, err)
		assert.Zero(t, calls, "construction must not resolve")

		values, present := e.Field("ParentImage")
		assert.True(t, present)
		assert.Equal(t, []string{"/Applications/X"}, values)
		assert.Equal(t, 1, calls)

		e.Field("ParentImage")
		assert.Equal(t, 1, calls, "resolved at most once per event")
	})

	t.Run("a resolver failure is reported, not read as no parent", func(t *testing.T) {
		t.Parallel()
		e, err := NewExecEventLazy(event(), func() (string, error) { return "", errors.New("graph down") })
		require.NoError(t, err)

		_, present := e.Field("ParentImage")
		assert.False(t, present)
		require.Error(t, e.ResolveErr())
		assert.Contains(t, e.ResolveErr().Error(), "graph down")
	})

	t.Run("a resolver returning no parent is not a failure", func(t *testing.T) {
		t.Parallel()
		e, err := NewExecEventLazy(event(), func() (string, error) { return "", nil })
		require.NoError(t, err)

		_, present := e.Field("ParentImage")
		assert.False(t, present)
		assert.NoError(t, e.ResolveErr(), "no parent and a failed lookup must be distinguishable")
	})

	t.Run("a malformed payload still errors before any resolution", func(t *testing.T) {
		t.Parallel()
		called := false
		_, err := NewExecEventLazy(api.Event{EventID: "e1", EventType: "exec", Payload: []byte(`{"path":123}`)},
			func() (string, error) { called = true; return "", nil })
		require.Error(t, err)
		assert.False(t, called, "a payload that does not decode is rejected without touching the graph")
	})

	t.Run("an event built without a resolver reports nothing", func(t *testing.T) {
		t.Parallel()
		e, err := NewEvent(event())
		require.NoError(t, err)
		_, present := e.Field("ParentImage")
		assert.False(t, present)
		assert.NoError(t, e.ResolveErr())
	})
}
