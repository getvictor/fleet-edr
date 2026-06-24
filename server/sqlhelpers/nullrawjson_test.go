package sqlhelpers

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

func TestNullRawJSON_Scan(t *testing.T) {
	t.Parallel()
	n := NullRawJSON(nil)

	require.NoError(t, n.Scan(nil), "nil scans to empty")
	assert.Nil(t, []byte(n))

	require.NoError(t, n.Scan([]byte(`{"key":"value"}`)))
	assert.JSONEq(t, `{"key":"value"}`, string(n))

	// Unsupported type produces a typed error.
	err := n.Scan(42)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported type")
}

func TestNullRawJSON_Scan_CopiesDriverBuffer(t *testing.T) {
	t.Parallel()
	// The MySQL driver reuses its scratch buffer across rows. Scan must copy or a subsequent scan will mutate the previously captured
	// payload.
	buf := []byte(`{"a":1}`)
	n := NullRawJSON(nil)
	require.NoError(t, n.Scan(buf))

	// Mutate the original buffer; the captured value must not change.
	buf[2] = 'X'
	assert.Equal(t, `{"a":1}`, string(n))
}

func TestNullRawJSON_Value(t *testing.T) {
	t.Parallel()
	var nilN NullRawJSON
	v, err := nilN.Value()
	require.NoError(t, err)
	assert.Nil(t, v, "nil RawJSON yields SQL NULL")

	literalNull := NullRawJSON("null")
	v, err = literalNull.Value()
	require.NoError(t, err)
	assert.Nil(t, v, "JSON null literal yields SQL NULL")

	concrete := NullRawJSON(`{"a":1}`)
	v, err = concrete.Value()
	require.NoError(t, err)
	assert.Equal(t, []byte(`{"a":1}`), v)
}

func TestNullRawJSON_MarshalJSON(t *testing.T) {
	t.Parallel()
	var nilN NullRawJSON
	out, err := nilN.MarshalJSON()
	require.NoError(t, err)
	assert.Equal(t, `null`, string(out))

	concrete := NullRawJSON(`{"x":true}`)
	out, err = concrete.MarshalJSON()
	require.NoError(t, err)
	assert.JSONEq(t, `{"x":true}`, string(out))
}

func TestNullRawJSON_UnmarshalJSON(t *testing.T) {
	t.Parallel()
	n := NullRawJSON(nil)
	require.NoError(t, n.UnmarshalJSON([]byte(`null`)))
	assert.Nil(t, []byte(n))

	require.NoError(t, n.UnmarshalJSON([]byte(`{"a":1}`)))
	assert.JSONEq(t, `{"a":1}`, string(n))
}

// ---- Property-based tests --------------------------------------------------
//
// PBT covers the algebraic identities that must hold for every valid
// JSON value (the input space is too large to enumerate in a table).

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

// TestNullRawJSON_RoundTripProperty: Unmarshal(Marshal(v)) preserves v for every JSON value; the "null" literal collapses to nil per
// the documented shape.
func TestNullRawJSON_RoundTripProperty(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		v := jsonValueGen().Draw(rt, "v")
		n := NullRawJSON(v)

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

// TestNullRawJSON_ScanValueProperty: Scan(Value(x)) reproduces x with
// the same nil/null collapse Value applies.
func TestNullRawJSON_ScanValueProperty(t *testing.T) {
	t.Parallel()
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
