//go:build integration

package integration

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rulesapi "github.com/fleetdm/edr/server/rules/api"
)

// spec:server-detection-rules-engine/a-rule-whose-identifier-cannot-be-persisted-is-refused-at-load/every-shipped-rule-identifier-is-storable
//
// TestRuleIDColumnsMatchTheDeclaredLimit is the contract test that makes "one permitted length" true rather than merely claimed.
//
// The requirement says every surface storing a rule identifier accepts the full permitted length, and that the length is defined
// in one place both the storage and the validation agree on. The validator reads api.MaxRuleIDLen, but the schema cannot: each
// column is an independent literal in a migration, five of them across two contexts. So the constant and the columns agreeing was
// an assertion in a proposal, not a property, and a typo or a later narrowing would recreate exactly the accepted-but-unstorable
// identifier that issue #832 was (issue #835 review).
//
// Asserted against the MIGRATED schema rather than by reading the SQL, so it covers what the database actually has after every
// migration in both corpora has run, including any later one that alters these columns again.
//
// Cross-context on purpose: alerts belongs to detection and the other four to rules, and the whole point is that they agree.
// Neither context's own test package can see both.
func TestRuleIDColumnsMatchTheDeclaredLimit(t *testing.T) {
	t.Parallel()
	stack := Setup(t)

	type column struct {
		Table string `db:"TABLE_NAME"`
		Chars int64  `db:"CHARACTER_MAXIMUM_LENGTH"`
	}
	var cols []column
	require.NoError(t, stack.DB.SelectContext(t.Context(), &cols, `
		SELECT TABLE_NAME, CHARACTER_MAXIMUM_LENGTH
		FROM information_schema.COLUMNS
		WHERE TABLE_SCHEMA = DATABASE() AND COLUMN_NAME = 'rule_id'
		ORDER BY TABLE_NAME`))

	// Every one of them, discovered rather than listed, so a NEW table that stores a rule identifier is covered the day it is
	// added instead of the day someone remembers to extend this list.
	require.NotEmpty(t, cols, "no rule_id columns found, so this test would pass vacuously")

	got := map[string]int64{}
	for _, c := range cols {
		got[c.Table] = c.Chars
		assert.EqualValuesf(t, rulesapi.MaxRuleIDLen, c.Chars,
			"%s.rule_id is VARCHAR(%d) but the loader accepts identifiers up to %d characters: a rule passing validation would "+
				"fail to store here, which is the shape of issue #832", c.Table, c.Chars, rulesapi.MaxRuleIDLen)
	}

	// The four the fix widened, named explicitly, because a migration that DROPPED one of these tables would otherwise let the
	// loop above pass over a shorter list. Asserted as presence, not as width, since the width is asserted for all of them above.
	for _, table := range []string{
		"alerts",
		"detection_rule_settings",
		"detection_exclusions",
		"detection_rule_match_counts",
	} {
		assert.Containsf(t, got, table, "%s stores a rule identifier and must be covered by this contract", table)
	}
}
