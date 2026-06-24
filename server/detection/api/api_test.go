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

// NullRawJSON's Scan/Value/Marshal/Unmarshal contracts are tested in server/sqlhelpers (the canonical home post-phase-6).
// detection/api re-exports the type via alias and only tests the detection-specific shapes here (JSONStringSlice, Event wire format,
// validation errors).

func TestJSONStringSlice_RoundTrip(t *testing.T) {
	t.Parallel()
	s := JSONStringSlice{"T1059", "T1105"}
	v, err := s.Value()
	require.NoError(t, err)
	require.NotNil(t, v)

	got := JSONStringSlice(nil)
	require.NoError(t, got.Scan(v.([]byte)))
	assert.Equal(t, s, got)

	// Empty / nil round-trip to NULL.
	var empty JSONStringSlice
	v, err = empty.Value()
	require.NoError(t, err)
	assert.Nil(t, v)

	nilGot := JSONStringSlice(nil)
	require.NoError(t, nilGot.Scan(nil))
	assert.Nil(t, nilGot)

	// String input also works (some drivers hand back string for JSON).
	fromStr := JSONStringSlice(nil)
	require.NoError(t, fromStr.Scan(`["T1083"]`))
	assert.Equal(t, JSONStringSlice{"T1083"}, fromStr)

	// Empty bytes scan to nil (NULL-equivalent).
	fromEmpty := JSONStringSlice(nil)
	require.NoError(t, fromEmpty.Scan([]byte{}))
	assert.Nil(t, fromEmpty)

	// Unsupported types return an error.
	bad := JSONStringSlice(nil)
	err = bad.Scan(42)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported type")
}

func TestIsValidationError(t *testing.T) {
	t.Parallel()
	assert.True(t, IsValidationError(ErrInvalidAlertTransition))
	assert.True(t, IsValidationError(ErrInvalidUserUpdater))
	assert.True(t, IsValidationError(fmt.Errorf("wrapped: %w", ErrInvalidAlertTransition)))
	assert.False(t, IsValidationError(ErrAlertNotFound))
	assert.False(t, IsValidationError(errors.New("random")))
	assert.False(t, IsValidationError(nil))
}

func TestEvent_RoundTripJSON(t *testing.T) {
	t.Parallel()
	// The agent depends on byte-identical wire shape for Event. Round-
	// trip an Event through json to pin the field set.
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
	t.Parallel()
	// Pin the wire-visible status strings so a future refactor can't
	// silently change the UI's expected values.
	assert.Equal(t, "open", string(AlertStatusOpen))
	assert.Equal(t, "acknowledged", string(AlertStatusAcknowledged))
	assert.Equal(t, "resolved", string(AlertStatusResolved))
}

func TestSeverity_Constants(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "low", SeverityLow)
	assert.Equal(t, "medium", SeverityMedium)
	assert.Equal(t, "high", SeverityHigh)
	assert.Equal(t, "critical", SeverityCritical)
}

func TestExitReason_Constants(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "event", ExitReasonEvent)
	assert.Equal(t, "ttl_reconciliation", ExitReasonTTLReconciliation)
	assert.Equal(t, "pid_reuse", ExitReasonPIDReuse)
	assert.Equal(t, "reexec", ExitReasonReExec)
	assert.Equal(t, "host_reconciled", ExitReasonHostReconciled)
}

// ---- Property-based tests --------------------------------------------------

// TestJSONStringSlice_RoundTripProperty: for any []string s,
// Scan(Value(s)) == s (with the empty-slice collapse to nil).
func TestJSONStringSlice_RoundTripProperty(t *testing.T) {
	t.Parallel()
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

// TestIsValidationError_Property: for any error wrapped any number of times around one of the validation sentinels, IsValidationError
// must return true. For any error not derived from a validation sentinel, it returns false.
func TestIsValidationError_Property(t *testing.T) {
	t.Parallel()
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
		for i := range wrapDepth {
			err = fmt.Errorf("wrap-%d: %w", i, err)
		}

		assert.Equal(rt, isValidation, IsValidationError(err),
			"IsValidationError must follow the wrap chain (depth=%d, isValidation=%v)",
			wrapDepth, isValidation)
	})
}
