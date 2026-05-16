package breakglass_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/identity/internal/breakglass"
)

// ValidatePassword enforces a rune-counted ≥ 12 floor. A regression that bytes-counted instead of rune-counted would let an operator
// satisfy the floor with three 4-byte runes; a regression that dropped the floor entirely would re-open the wave-0 weak-password
// surface that motivated Phase 4 in the first place.
func TestValidatePassword(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		input   string
		wantErr error
	}{
		{"empty rejects", "", breakglass.ErrPasswordTooShort},
		{"11 ascii rejects", strings.Repeat("a", 11), breakglass.ErrPasswordTooShort},
		{"12 ascii accepts", strings.Repeat("a", 12), nil},
		{"100 ascii accepts (no upper bound)", strings.Repeat("a", 100), nil},
		// Rune counting: a single emoji is 4 bytes but 1 rune. 11 emojis (44 bytes) must still reject so a multi-byte password
		// cannot game the byte-count.
		{"11 emojis rejects (rune-count, not byte-count)", strings.Repeat("🔑", 11), breakglass.ErrPasswordTooShort},
		{"12 emojis accepts", strings.Repeat("🔑", 12), nil},
		// Diceware-style passphrase: spaces count as runes.
		{"3-word passphrase rejects (length 11)", "ten char yo", breakglass.ErrPasswordTooShort},
		{"4-word passphrase accepts", "correct horse battery staple", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := breakglass.ValidatePassword(tc.input)
			if tc.wantErr == nil {
				require.NoError(t, err)
				return
			}
			assert.ErrorIs(t, err, tc.wantErr)
		})
	}
}
