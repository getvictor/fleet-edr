package ssoconfig

import (
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// Any list of group mappings survives the group_roles column: encoded as the store writes it and decoded as it reads it back, the
// pairs are the same, in the same order, and no pairs read back as none.
func TestGroupRoles_RoundTripThroughTheColumn_PBT(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		pairs := rapid.SliceOf(rapid.Custom(func(rt *rapid.T) GroupRole {
			return GroupRole{Group: rapid.String().Draw(rt, "group"), Role: rapid.String().Draw(rt, "role")}
		})).Draw(rt, "pairs")

		encoded := encodeGroupRoles(pairs)
		if len(pairs) == 0 {
			require.Nil(rt, encoded, "no pairs store NULL")
		}
		cfg, err := toConfig(&row{GroupRoles: encoded})
		require.NoError(rt, err)
		if len(pairs) == 0 {
			require.Empty(rt, cfg.GroupRoles)
			return
		}
		require.Equal(rt, pairs, cfg.GroupRoles)
	})
}
