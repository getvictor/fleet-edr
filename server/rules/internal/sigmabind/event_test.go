package sigmabind

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/rules/api"
)

func event(eventType, payload string) api.Event {
	return api.Event{EventID: "e1", HostID: "h1", EventType: eventType, Payload: []byte(payload)}
}

// spec:server-detection-rules-engine/our-events-supply-the-sigma-fields-a-rule-reads/our-events-supply-the-sigma-fields-a-rule-reads
//
// TestEvent_ExtractsMappedFields uses payload shapes captured from a real macOS host rather than invented ones, because the detail
// that matters here only shows up in real data: argv[0] is whatever the caller passed, sometimes a full path (/usr/sbin/sshd) and
// sometimes a bare name (xpcproxy).
func TestEvent_ExtractsMappedFields(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		event       api.Event
		field       string
		wantValues  []string
		wantPresent bool
	}{
		{
			"exec Image is the resolved executable path",
			event("exec", `{"pid":501,"ppid":1,"path":"/usr/sbin/sshd","args":["/usr/sbin/sshd","-i"]}`),
			"Image", []string{"/usr/sbin/sshd"}, true,
		},
		{
			"exec CommandLine joins argv",
			event("exec", `{"pid":501,"ppid":1,"path":"/usr/sbin/sshd","args":["/usr/sbin/sshd","-i"]}`),
			"CommandLine", []string{"/usr/sbin/sshd -i"}, true,
		},
		{
			// Real capture: argv[0] is the bare name while path is the resolved binary. Image stays authoritative for the path.
			"argv[0] may be a bare name while Image is the full path",
			event("exec", `{"pid":8,"ppid":1,"path":"/usr/libexec/xpcproxy","args":["xpcproxy","com.openssh.sshd.EEEC"]}`),
			"CommandLine", []string{"xpcproxy com.openssh.sshd.EEEC"}, true,
		},
		{
			"and Image for that same event is still the resolved path",
			event("exec", `{"pid":8,"ppid":1,"path":"/usr/libexec/xpcproxy","args":["xpcproxy","com.openssh.sshd.EEEC"]}`),
			"Image", []string{"/usr/libexec/xpcproxy"}, true,
		},
		{
			"a single-argument exec has a CommandLine of just argv[0]",
			event("exec", `{"pid":9,"ppid":1,"path":"/tmp/blocked-tool","args":["/tmp/blocked-tool"]}`),
			"CommandLine", []string{"/tmp/blocked-tool"}, true,
		},
		{
			"open TargetFilename is the opened path",
			// O_RDWR|O_TRUNC: a modification, which is the only shape that supplies the path (#801).
			event("open", `{"pid":77,"path":"/etc/sudoers","flags":1026}`),
			"TargetFilename", []string{"/etc/sudoers"}, true,
		},
		{
			"a field this event type does not supply is absent",
			event("open", `{"pid":77,"path":"/etc/sudoers","flags":2}`),
			"CommandLine", nil, false,
		},
		{
			"a field no event type supplies is absent",
			event("exec", `{"pid":1,"ppid":0,"path":"/bin/sh","args":["/bin/sh"]}`),
			"ParentImage", nil, false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e, err := NewEvent(tc.event)
			require.NoError(t, err)
			values, present := e.Field(tc.field)
			assert.Equal(t, tc.wantPresent, present)
			assert.Equal(t, tc.wantValues, values)
		})
	}
}

// TestEvent_AbsentVersusEmpty pins the two collapses this mapping makes deliberately, both of which change what a `null` rule
// matches.
func TestEvent_AbsentVersusEmpty(t *testing.T) {
	t.Parallel()

	t.Run("an exec with no arguments supplies no CommandLine", func(t *testing.T) {
		t.Parallel()
		// The corpus contains a rule filtering on `CommandLine: null` to skip execs with no command line; reporting an empty
		// string instead would stop that filter from matching what its author meant.
		e, err := NewEvent(event("exec", `{"pid":1,"ppid":0,"path":"/bin/sh","args":[]}`))
		require.NoError(t, err)
		_, present := e.Field("CommandLine")
		assert.False(t, present)
	})

	t.Run("an empty path is reported as absent, not as an empty value", func(t *testing.T) {
		t.Parallel()
		// path is required by the event schema, so an empty one is a malformed event. Reporting it present-and-empty would let a
		// rule written `Image: ''` match every malformed event.
		e, err := NewEvent(event("exec", `{"pid":1,"ppid":0,"path":"","args":["sh"]}`))
		require.NoError(t, err)
		_, present := e.Field("Image")
		assert.False(t, present)
	})
}

// TestNewEvent_MalformedPayloadIsAnError separates a malformed event from an uninteresting one: the first is worth surfacing, the
// second is routine.
func TestNewEvent_MalformedPayloadIsAnError(t *testing.T) {
	t.Parallel()

	_, err := NewEvent(event("exec", `{"path": 12345}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode exec payload")
	assert.Contains(t, err.Error(), "e1", "the error names the event, since a batch may contain thousands")

	_, err = NewEvent(event("open", `not json`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode open payload")
}

// TestNewEvent_UnmappedTypeSuppliesNothing confirms an unmapped type is routine rather than an error: a batch mixes event types and
// a rule only runs against the one its logsource names.
func TestNewEvent_UnmappedTypeSuppliesNothing(t *testing.T) {
	t.Parallel()

	e, err := NewEvent(event("dns_query", `{"pid":1,"query":"example.com"}`))
	require.NoError(t, err)
	assert.Equal(t, "dns_query", e.EventType())
	_, present := e.Field("Image")
	assert.False(t, present)
}

// TestEvent_FieldIsAllocationFree pins the property the acceptance criterion asks for. Decoding allocates once per event, but the
// per-rule cost has to be a lookup: this path runs for every field, of every rule, against every event.
//
//nolint:paralleltest // testing.AllocsPerRun panics when called from a parallel test: it needs the allocation counters to itself.
func TestEvent_FieldIsAllocationFree(t *testing.T) {
	// Deliberately NOT parallel: testing.AllocsPerRun panics when called from a parallel test, since it needs the allocation
	// counters to itself.
	e, err := NewEvent(event("exec", `{"pid":1,"ppid":0,"path":"/usr/bin/curl","args":["curl","-O","http://x"]}`))
	require.NoError(t, err)

	allocs := testing.AllocsPerRun(200, func() {
		if _, ok := e.Field("Image"); !ok {
			t.Fatal("Image must be present")
		}
		if _, ok := e.Field("CommandLine"); !ok {
			t.Fatal("CommandLine must be present")
		}
		e.Field("ParentImage")
	})
	assert.Zero(t, allocs, "field access must not allocate")
}

// spec:server-detection-rules-engine/our-events-supply-the-sigma-fields-a-rule-reads/a-read-only-open-supplies-no-target-filename
// spec:server-detection-rules-engine/our-events-supply-the-sigma-fields-a-rule-reads/a-lock-supplies-no-target-filename
//
// TestEvent_FileEventMeansACompletedModification pins the two shapes that supply no TargetFilename: a read-only open, and an open
// that can write but sets no content-changing flag.
//
// Sigma's file_event category is file creation or modification (it is Sysmon's FileCreate), not "a file was opened". Read-only
// opens of a watched path are routine: cron, sudo itself and various PAM modules read /etc/sudoers constantly. Locks are the same
// noise wearing write access, and measurably so: sudo opens /etc/sudoers O_WRONLY to take a LOCK_EX flock and never writes, which
// put 30 sudoers_tamper alerts on one host in 15 minutes during rc.6 QA. Supplying either would present known noise to every
// file_event rule as a detection, which is why the gate is here rather than in each rule (#801).
func TestEvent_FileEventMeansACompletedModification(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		flags       int
		wantPresent bool
	}{
		{"O_RDONLY supplies nothing", 0x0, false},
		{"O_WRONLY alone is a lock, not a modification", 0x1, false},
		{"O_RDWR alone is a lock, not a modification", 0x2, false},
		{"O_WRONLY|O_TRUNC supplies the path", 0x1 | 0x400, true},
		{"O_WRONLY|O_APPEND supplies the path", 0x1 | 0x8, true},
		// The flags every real open event in the dev corpus carries: O_WRONLY|O_CREAT|O_TRUNC.
		{"O_WRONLY|O_CREAT|O_TRUNC supplies the path", 0x601, true},
		// A read-only open that also sets high bits is still read-only: only bits 0-1 carry the access mode.
		{"O_RDONLY|O_CLOEXEC is still read-only", 0x1000000, false},
		// O_APPEND without write access is not a modification either: the mutating bits alone are not enough.
		{"O_APPEND without write access supplies nothing", 0x8, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e, err := NewEvent(api.Event{
				EventID: "e1", EventType: "open",
				Payload: []byte(fmt.Sprintf(`{"pid":1,"path":"/etc/sudoers","flags":%d}`, tc.flags)),
			})
			require.NoError(t, err)
			_, present := e.Field("TargetFilename")
			assert.Equal(t, tc.wantPresent, present)
		})
	}
}

// FuzzNewEvent exercises the payload decoder with fuzzer-supplied bytes. CLAUDE.md's test matrix names event JSON as a fuzz target,
// and this is the package that turns untrusted payload bytes into the values a detection matches on.
//
// The invariants are the ones a caller relies on: the adapter never panics, an error and a usable event are mutually exclusive, and
// a field is never reported present with no values, since a present-but-valueless field would make `Field: null` and a real value
// indistinguishable downstream.
func FuzzNewEvent(f *testing.F) {
	f.Add("exec", `{"pid":1,"ppid":0,"path":"/bin/sh","args":["sh","-c","x"]}`)
	f.Add("exec", `{"args":[],"path":"","snapshot":true}`)
	f.Add("open", `{"pid":1,"path":"/etc/sudoers","flags":1537}`)
	f.Add("open", `{"pid":1,"path":"/etc/sudoers","flags":0}`)
	f.Add("dns_query", `{"query":"example.com"}`)
	f.Add("exec", `{"args":null,"path":null}`)
	f.Add("exec", `null`)
	f.Add("exec", `{}`)

	f.Fuzz(func(t *testing.T, eventType, payload string) {
		e, err := NewEvent(api.Event{EventID: "fuzz", EventType: eventType, Payload: []byte(payload)})
		if err != nil {
			if e != nil {
				t.Fatalf("an error must not also return an event: %v", err)
			}
			return
		}
		if e == nil {
			t.Fatal("no error but no event")
		}
		if e.EventType() != eventType {
			t.Fatalf("event type %q became %q", eventType, e.EventType())
		}
		for _, name := range []string{"Image", "CommandLine", "TargetFilename", "ParentImage", ""} {
			values, present := e.Field(name)
			if present && len(values) == 0 {
				t.Fatalf("field %q reported present with no values", name)
			}
			if !present && values != nil {
				t.Fatalf("field %q reported absent but returned %v", name, values)
			}
		}
	})
}

// spec:server-detection-rules-engine/an-open-event-supplies-the-writer/the-writing-process-image-is-available-to-a-file-rule
//
// TestEvent_OpenSuppliesTheWritingProcessImage pins that a file rule can match on who did the opening. The value is resolved
// lazily, because a rule that never reads Image must not pay for a process lookup on every open event.
func TestEvent_OpenSuppliesTheWritingProcessImage(t *testing.T) {
	t.Parallel()

	t.Run("resolved on first read", func(t *testing.T) {
		t.Parallel()
		calls := 0
		e, err := NewOpenEventLazy(
			api.Event{EventID: "e1", EventType: "open", Payload: []byte(`{"pid":9,"path":"/etc/sudoers","flags":1537}`)},
			func() (string, error) { calls++; return "/usr/bin/sudo", nil })
		require.NoError(t, err)

		image, ok := e.Field("Image")
		require.True(t, ok)
		assert.Equal(t, []string{"/usr/bin/sudo"}, image)

		_, _ = e.Field("Image")
		assert.Equal(t, 1, calls, "the lookup is memoized, not repeated per field read")
		assert.NoError(t, e.ResolveErr())
	})

	t.Run("never read means never resolved", func(t *testing.T) {
		t.Parallel()
		calls := 0
		e, err := NewOpenEventLazy(
			api.Event{EventID: "e1", EventType: "open", Payload: []byte(`{"pid":9,"path":"/etc/sudoers","flags":1537}`)},
			func() (string, error) { calls++; return "/usr/bin/sudo", nil })
		require.NoError(t, err)

		_, _ = e.Field("TargetFilename")
		assert.Zero(t, calls)
	})

	t.Run("a failed lookup declines rather than matching", func(t *testing.T) {
		t.Parallel()
		e, err := NewOpenEventLazy(
			api.Event{EventID: "e1", EventType: "open", Payload: []byte(`{"pid":9,"path":"/etc/sudoers","flags":1537}`)},
			func() (string, error) { return "", errors.New("graph unavailable") })
		require.NoError(t, err)

		_, ok := e.Field("Image")
		assert.False(t, ok, "an unresolvable image is absent, not empty: a rule matching Image must not match on a lookup failure")
		require.Error(t, e.ResolveErr())
	})
}

// TestWithResolver_SharesTheDecodeButNotTheError is the property that lets several rules share one decoded event.
//
// The decode and the argv derivations are pure and expensive, so copies share them. The resolver state is not shared, because
// ResolveErr is read per rule: a rule that never looked at the supplied image must not inherit another rule's graph failure, which
// would discard its findings for the whole batch over a lookup it did not make.
func TestWithResolver_SharesTheDecodeButNotTheError(t *testing.T) {
	t.Parallel()

	payload := []byte(`{"pid":1,"path":"/usr/bin/curl","args":["curl","https://example.test"]}`)
	core, err := NewEvent(api.Event{EventID: "e1", EventType: "exec", Payload: payload})
	require.NoError(t, err)

	// One memoizing lookup behind both copies: the graph is read once per event however many rules ask.
	lookups := 0
	shared := func() (string, error) {
		lookups++
		return "", assert.AnError
	}

	asked := core.WithResolver(shared)
	silent := core.WithResolver(shared)

	// Both copies see the decoded fields without decoding again.
	for name, ev := range map[string]*Event{"asked": asked, "silent": silent} {
		values, ok := ev.Field("CommandLine")
		require.True(t, ok, "%s lost the shared decode", name)
		assert.Equal(t, []string{"curl https://example.test"}, values)
	}

	// Only one copy reaches the resolver.
	_, _ = asked.Field("ParentImage")

	assert.Equal(t, 1, lookups, "the memoizing resolver is shared, so the graph is read once")
	require.Error(t, asked.ResolveErr(), "the rule that asked sees the failure")
	assert.NoError(t, silent.ResolveErr(), "the rule that never asked must not inherit it")
}

// TestWithResolver_DoesNotMutateTheOriginal pins that a copy cannot write back through the shared fields.
func TestWithResolver_DoesNotMutateTheOriginal(t *testing.T) {
	t.Parallel()

	payload := []byte(`{"pid":1,"path":"/bin/sh","args":["sh"]}`)
	core, err := NewEvent(api.Event{EventID: "e1", EventType: "exec", Payload: payload})
	require.NoError(t, err)

	copied := core.WithResolver(func() (string, error) { return "/usr/bin/parent", nil })
	values, ok := copied.Field("ParentImage")
	require.True(t, ok)
	assert.Equal(t, []string{"/usr/bin/parent"}, values)

	_, present := core.Field("ParentImage")
	assert.False(t, present, "resolving on a copy must not give the original a parent it never had")
}
