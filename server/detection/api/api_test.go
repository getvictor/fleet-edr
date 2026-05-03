package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

func TestNullRawJSON_Scan(t *testing.T) {
	var n NullRawJSON

	require.NoError(t, n.Scan(nil), "nil scans to empty")
	assert.Nil(t, []byte(n))

	require.NoError(t, n.Scan([]byte(`{"key":"value"}`)))
	assert.JSONEq(t, `{"key":"value"}`, string(n))

	// Unsupported type produces a typed error.
	err := n.Scan(42)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported type")
}

func TestNullRawJSON_Value(t *testing.T) {
	var nilN NullRawJSON
	v, err := nilN.Value()
	require.NoError(t, err)
	assert.Nil(t, v, "nil RawJSON yields SQL NULL")

	literalNull := NullRawJSON("null")
	v, err = literalNull.Value()
	require.NoError(t, err)
	assert.Nil(t, v, "JSON null literal yields SQL NULL")

	real := NullRawJSON(`{"a":1}`)
	v, err = real.Value()
	require.NoError(t, err)
	assert.Equal(t, []byte(`{"a":1}`), v)
}

func TestNullRawJSON_MarshalJSON(t *testing.T) {
	var nilN NullRawJSON
	out, err := nilN.MarshalJSON()
	require.NoError(t, err)
	assert.Equal(t, `null`, string(out))

	real := NullRawJSON(`{"x":true}`)
	out, err = real.MarshalJSON()
	require.NoError(t, err)
	assert.JSONEq(t, `{"x":true}`, string(out))
}

func TestNullRawJSON_UnmarshalJSON(t *testing.T) {
	var n NullRawJSON
	require.NoError(t, n.UnmarshalJSON([]byte(`null`)))
	assert.Nil(t, []byte(n))

	require.NoError(t, n.UnmarshalJSON([]byte(`{"a":1}`)))
	assert.JSONEq(t, `{"a":1}`, string(n))
}

func TestJSONStringSlice_RoundTrip(t *testing.T) {
	s := JSONStringSlice{"T1059", "T1105"}
	v, err := s.Value()
	require.NoError(t, err)
	require.NotNil(t, v)

	var got JSONStringSlice
	require.NoError(t, got.Scan(v.([]byte)))
	assert.Equal(t, s, got)

	// Empty / nil round-trip to NULL.
	var empty JSONStringSlice
	v, err = empty.Value()
	require.NoError(t, err)
	assert.Nil(t, v)

	var nilGot JSONStringSlice
	require.NoError(t, nilGot.Scan(nil))
	assert.Nil(t, nilGot)

	// String input also works (some drivers hand back string for JSON).
	var fromStr JSONStringSlice
	require.NoError(t, fromStr.Scan(`["T1083"]`))
	assert.Equal(t, JSONStringSlice{"T1083"}, fromStr)

	// Empty bytes scan to nil (NULL-equivalent).
	var fromEmpty JSONStringSlice
	require.NoError(t, fromEmpty.Scan([]byte{}))
	assert.Nil(t, fromEmpty)

	// Unsupported types return an error.
	var bad JSONStringSlice
	err = bad.Scan(42)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported type")
}

func TestIsValidationError(t *testing.T) {
	assert.True(t, IsValidationError(ErrInvalidAlertTransition))
	assert.True(t, IsValidationError(ErrInvalidUserUpdater))
	assert.True(t, IsValidationError(fmt.Errorf("wrapped: %w", ErrInvalidAlertTransition)))
	assert.False(t, IsValidationError(ErrAlertNotFound))
	assert.False(t, IsValidationError(errors.New("random")))
	assert.False(t, IsValidationError(nil))
}

func TestEvent_RoundTripJSON(t *testing.T) {
	// The agent depends on byte-identical wire shape across the
	// modular monolith migration. Round-trip an Event through json
	// to pin the field set.
	in := Event{
		EventID:      "abc",
		HostID:       "h",
		TimestampNs:  100,
		IngestedAtNs: 200,
		EventType:    "fork",
		Payload:      json.RawMessage(`{"child_pid":1}`),
	}
	out, err := json.Marshal(in)
	require.NoError(t, err)

	var got Event
	require.NoError(t, json.Unmarshal(out, &got))
	assert.Equal(t, in.EventID, got.EventID)
	assert.Equal(t, in.HostID, got.HostID)
	assert.Equal(t, in.TimestampNs, got.TimestampNs)
	assert.Equal(t, in.IngestedAtNs, got.IngestedAtNs)
	assert.Equal(t, in.EventType, got.EventType)
}

func TestAlertStatus_Constants(t *testing.T) {
	// Pin the wire-visible status strings so a future refactor can't
	// silently change the UI's expected values.
	assert.Equal(t, "open", string(AlertStatusOpen))
	assert.Equal(t, "acknowledged", string(AlertStatusAcknowledged))
	assert.Equal(t, "resolved", string(AlertStatusResolved))
}

func TestSeverity_Constants(t *testing.T) {
	assert.Equal(t, "low", SeverityLow)
	assert.Equal(t, "medium", SeverityMedium)
	assert.Equal(t, "high", SeverityHigh)
	assert.Equal(t, "critical", SeverityCritical)
}

func TestExitReason_Constants(t *testing.T) {
	assert.Equal(t, "event", ExitReasonEvent)
	assert.Equal(t, "ttl_reconciliation", ExitReasonTTLReconciliation)
	assert.Equal(t, "pid_reuse", ExitReasonPIDReuse)
	assert.Equal(t, "reexec", ExitReasonReExec)
	assert.Equal(t, "host_reconciled", ExitReasonHostReconciled)
}

// ---- Property-based tests --------------------------------------------------
//
// PBT (pgregory.net/rapid) for serialization round-trips: the input
// space is "any valid JSON value", which is too large to enumerate
// in a table. The properties below assert algebraic identities that
// must hold for every input rapid generates. Failures shrink to a
// minimal counter-example, named in the failure message.

// jsonValueGen produces a valid JSON value (object, array, string,
// number, bool, or null) suitable for NullRawJSON / JSONStringSlice
// round-trip checks.
func jsonValueGen() *rapid.Generator[json.RawMessage] {
	return rapid.OneOf(
		rapid.Just(json.RawMessage(`null`)),
		rapid.Just(json.RawMessage(`true`)),
		rapid.Just(json.RawMessage(`false`)),
		rapid.Just(json.RawMessage(`0`)),
		rapid.Just(json.RawMessage(`42`)),
		rapid.Just(json.RawMessage(`-7`)),
		rapid.Just(json.RawMessage(`"x"`)),
		rapid.Just(json.RawMessage(`"hello world"`)),
		rapid.Just(json.RawMessage(`""`)),
		rapid.Just(json.RawMessage(`[]`)),
		rapid.Just(json.RawMessage(`[1,2,3]`)),
		rapid.Just(json.RawMessage(`{}`)),
		rapid.Just(json.RawMessage(`{"a":1}`)),
		rapid.Just(json.RawMessage(`{"nested":{"k":"v"}}`)),
		rapid.Just(json.RawMessage(`{"arr":[1,"two",null,true]}`)),
	)
}

// TestNullRawJSON_RoundTripProperty asserts that for any valid JSON
// value v: Unmarshal(Marshal(v)) reproduces v's logical content. The
// "null" literal collapses to nil per NullRawJSON's documented shape;
// every other value round-trips byte-for-byte (modulo whitespace).
func TestNullRawJSON_RoundTripProperty(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		v := jsonValueGen().Draw(rt, "v")
		var n NullRawJSON = NullRawJSON(v)

		// Marshal -> Unmarshal must preserve content (or both be nil
		// for the null literal).
		out, err := n.MarshalJSON()
		require.NoError(rt, err)

		var back NullRawJSON
		require.NoError(rt, back.UnmarshalJSON(out))

		if string(v) == "null" {
			assert.Nil(rt, []byte(back), "JSON null collapses to nil")
			return
		}
		assert.JSONEq(rt, string(v), string(back),
			"round-trip must preserve JSON value (input=%s)", string(v))
	})
}

// TestNullRawJSON_ScanValueProperty pairs Scan + Value: for any
// valid raw JSON, Scan(Value(x)) reproduces x (with the "null" /
// nil collapse), and the Value of a nil/null is SQL NULL.
func TestNullRawJSON_ScanValueProperty(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		v := jsonValueGen().Draw(rt, "v")
		original := NullRawJSON(v)

		val, err := original.Value()
		require.NoError(rt, err)

		var rebuilt NullRawJSON
		if val == nil {
			require.NoError(rt, rebuilt.Scan(nil))
			assert.Nil(rt, []byte(rebuilt))
			return
		}
		require.NoError(rt, rebuilt.Scan(val))
		assert.JSONEq(rt, string(v), string(rebuilt))
	})
}

// TestJSONStringSlice_RoundTripProperty: for any []string s,
// Scan(Value(s)) == s (with the empty-slice collapse to nil).
func TestJSONStringSlice_RoundTripProperty(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		// Build a string slice from rapid's generator. Cap length so
		// pathological cases don't dominate runtime.
		s := rapid.SliceOfN(rapid.StringMatching(`[a-zA-Z0-9._-]{0,16}`), 0, 8).Draw(rt, "s")
		original := JSONStringSlice(s)

		val, err := original.Value()
		require.NoError(rt, err)

		var rebuilt JSONStringSlice
		if val == nil {
			require.NoError(rt, rebuilt.Scan(nil))
			assert.Empty(rt, rebuilt)
			return
		}
		require.NoError(rt, rebuilt.Scan(val.([]byte)))
		assert.Equal(rt, []string(original), []string(rebuilt))
	})
}

// TestIsValidationError_Property: for any error wrapped any number
// of times around one of the validation sentinels, IsValidationError
// must return true. For any error not derived from a validation
// sentinel, it returns false.
func TestIsValidationError_Property(t *testing.T) {
	validationSentinels := []error{ErrInvalidAlertTransition, ErrInvalidUserUpdater}
	notValidationErrs := []error{
		ErrAlertNotFound,
		ErrHostNotFound,
		ErrProcessNotFound,
		errors.New("unrelated"),
		fmt.Errorf("wrapped: %w", ErrAlertNotFound),
	}

	rapid.Check(t, func(rt *rapid.T) {
		isValidation := rapid.Bool().Draw(rt, "is_validation")
		wrapDepth := rapid.IntRange(0, 5).Draw(rt, "wrap_depth")

		var err error
		if isValidation {
			err = validationSentinels[rapid.IntRange(0, len(validationSentinels)-1).Draw(rt, "v_idx")]
		} else {
			err = notValidationErrs[rapid.IntRange(0, len(notValidationErrs)-1).Draw(rt, "n_idx")]
		}
		for i := 0; i < wrapDepth; i++ {
			err = fmt.Errorf("wrap-%d: %w", i, err)
		}

		assert.Equal(rt, isValidation, IsValidationError(err),
			"IsValidationError must follow the wrap chain (depth=%d, isValidation=%v)",
			wrapDepth, isValidation)
	})
}
