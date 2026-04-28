package envparse

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// envFn returns a Getenv backed by a static map, so each test names exactly
// the variables it cares about.
func envFn(m map[string]string) Getenv {
	return func(k string) string { return m[k] }
}

func TestPositiveInt(t *testing.T) {
	cases := []struct {
		name     string
		env      string
		want     int
		wantUnch bool
		wantErr  string
	}{
		{name: "unset leaves default untouched", env: "", want: 100, wantUnch: true},
		{name: "valid positive", env: "42", want: 42},
		{name: "zero rejected", env: "0", want: 100, wantUnch: true, wantErr: "must be positive"},
		{name: "negative rejected", env: "-3", want: 100, wantUnch: true, wantErr: "must be positive"},
		{name: "non-numeric rejected", env: "abc", want: 100, wantUnch: true, wantErr: "K=\"abc\""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dst := 100
			var errs []error
			PositiveInt(envFn(map[string]string{"K": tc.env}), "K", &dst, &errs)
			assert.Equal(t, tc.want, dst)
			if tc.wantErr == "" {
				assert.Empty(t, errs)
			} else {
				require.Len(t, errs, 1)
				assert.Contains(t, errs[0].Error(), tc.wantErr)
			}
		})
	}
}

func TestNonNegativeInt(t *testing.T) {
	cases := []struct {
		name    string
		env     string
		want    int
		wantErr string
	}{
		{name: "unset", env: "", want: 30},
		{name: "valid positive", env: "90", want: 90},
		{name: "zero accepted as disabled sentinel", env: "0", want: 0},
		{name: "negative rejected", env: "-1", want: 30, wantErr: "must be >= 0"},
		{name: "garbage rejected", env: "x", want: 30, wantErr: "K=\"x\""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dst := 30
			var errs []error
			NonNegativeInt(envFn(map[string]string{"K": tc.env}), "K", &dst, &errs)
			assert.Equal(t, tc.want, dst)
			if tc.wantErr == "" {
				assert.Empty(t, errs)
			} else {
				require.Len(t, errs, 1)
				assert.Contains(t, errs[0].Error(), tc.wantErr)
			}
		})
	}
}

func TestNonNegativeInt64(t *testing.T) {
	const def int64 = 500 * 1024 * 1024
	cases := []struct {
		name    string
		env     string
		want    int64
		wantErr string
	}{
		{name: "unset", env: "", want: def},
		{name: "valid", env: "1073741824", want: 1073741824},
		{name: "zero accepted", env: "0", want: 0},
		{name: "negative rejected", env: "-1", want: def, wantErr: "must be >= 0"},
		{name: "garbage rejected", env: "10MB", want: def, wantErr: "K=\"10MB\""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dst := def
			var errs []error
			NonNegativeInt64(envFn(map[string]string{"K": tc.env}), "K", &dst, &errs)
			assert.Equal(t, tc.want, dst)
			if tc.wantErr == "" {
				assert.Empty(t, errs)
			} else {
				require.Len(t, errs, 1)
				assert.Contains(t, errs[0].Error(), tc.wantErr)
			}
		})
	}
}

func TestPositiveDuration(t *testing.T) {
	const def = time.Second
	cases := []struct {
		name    string
		env     string
		want    time.Duration
		wantErr string
	}{
		{name: "unset", env: "", want: def},
		{name: "valid 5s", env: "5s", want: 5 * time.Second},
		{name: "valid 1h", env: "1h", want: time.Hour},
		{name: "zero rejected (would panic ticker)", env: "0", want: def, wantErr: "must be positive"},
		{name: "negative rejected", env: "-30s", want: def, wantErr: "must be positive"},
		{name: "garbage rejected", env: "fortnight", want: def, wantErr: "K=\"fortnight\""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dst := def
			var errs []error
			PositiveDuration(envFn(map[string]string{"K": tc.env}), "K", &dst, &errs)
			assert.Equal(t, tc.want, dst)
			if tc.wantErr == "" {
				assert.Empty(t, errs)
			} else {
				require.Len(t, errs, 1)
				assert.Contains(t, errs[0].Error(), tc.wantErr)
			}
		})
	}
}

func TestNonNegativeDuration(t *testing.T) {
	const def = time.Minute
	cases := []struct {
		name    string
		env     string
		want    time.Duration
		wantErr string
	}{
		{name: "unset", env: "", want: def},
		{name: "valid 30s", env: "30s", want: 30 * time.Second},
		{name: "zero accepted as disabled sentinel", env: "0", want: 0},
		{name: "0s accepted", env: "0s", want: 0},
		{name: "negative rejected", env: "-1s", want: def, wantErr: "must be >= 0"},
		{name: "garbage rejected", env: "??", want: def, wantErr: "K=\"??\""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dst := def
			var errs []error
			NonNegativeDuration(envFn(map[string]string{"K": tc.env}), "K", &dst, &errs)
			assert.Equal(t, tc.want, dst)
			if tc.wantErr == "" {
				assert.Empty(t, errs)
			} else {
				require.Len(t, errs, 1)
				assert.Contains(t, errs[0].Error(), tc.wantErr)
			}
		})
	}
}

func TestAllowlist(t *testing.T) {
	t.Run("empty input returns nil", func(t *testing.T) {
		assert.Nil(t, Allowlist(""))
		assert.Nil(t, Allowlist("   "))
	})

	t.Run("single value", func(t *testing.T) {
		got := Allowlist("/usr/libexec/sshd-session")
		require.NotNil(t, got)
		_, ok := got["/usr/libexec/sshd-session"]
		assert.True(t, ok)
		assert.Len(t, got, 1)
	})

	t.Run("comma-separated values", func(t *testing.T) {
		got := Allowlist("a,b,c")
		assert.Len(t, got, 3)
		for _, k := range []string{"a", "b", "c"} {
			_, ok := got[k]
			assert.True(t, ok, "expected %q in allowlist", k)
		}
	})

	t.Run("trims whitespace and drops empty entries", func(t *testing.T) {
		got := Allowlist(" /a , /b ,, /c ,")
		assert.Len(t, got, 3)
		for _, k := range []string{"/a", "/b", "/c"} {
			_, ok := got[k]
			assert.True(t, ok, "expected %q in allowlist", k)
		}
		// no empty-string key
		_, hasEmpty := got[""]
		assert.False(t, hasEmpty)
	})

	t.Run("exact-string keys (no normalisation)", func(t *testing.T) {
		// Allowlist is the raw membership set; case is preserved exactly,
		// because the caller compares against actual filesystem paths.
		got := Allowlist("/Foo,/foo")
		assert.Len(t, got, 2)
	})
}

// errFmt sanity-check: every parse-failure error mentions the key + value so
// log readers can trace which env var caused the misconfig. Locked in via a
// substring assertion against one representative path through each parser.
func TestParseErrorsCarryKeyAndValue(t *testing.T) {
	check := func(t *testing.T, errs []error, wantKey, wantVal string) {
		t.Helper()
		require.Len(t, errs, 1)
		s := errs[0].Error()
		assert.Contains(t, s, wantKey)
		assert.Contains(t, s, wantVal,
			"want error to mention value %q, got %q", wantVal, s)
	}

	t.Run("PositiveInt", func(t *testing.T) {
		dst := 1
		var errs []error
		PositiveInt(envFn(map[string]string{"K": "abc"}), "K", &dst, &errs)
		check(t, errs, "K", "abc")
	})
	t.Run("NonNegativeInt64", func(t *testing.T) {
		var dst int64 = 1
		var errs []error
		NonNegativeInt64(envFn(map[string]string{"K": "1eb"}), "K", &dst, &errs)
		check(t, errs, "K", "1eb")
	})
	t.Run("PositiveDuration", func(t *testing.T) {
		dst := time.Second
		var errs []error
		PositiveDuration(envFn(map[string]string{"K": "abc"}), "K", &dst, &errs)
		check(t, errs, "K", "abc")
	})
}
