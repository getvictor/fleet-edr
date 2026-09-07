package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// spec:server-detection-rules-engine/operator-toggling-of-individual-rules/a-severity-override-adjusts-an-escalation-rather-than-erasing-it
//
// TestApplyModifiers_OrderingSurvivesEveryOverride is the property issue #753 is actually about, and it is asserted as an ORDERING
// rather than as a table of expected bands.
//
// The defect was not that any band was wrong on its own. It was that an operator who found a rule noisy and lowered it got the
// same answer for an escalated finding and an ordinary one, so the population they would most want to keep visible became
// indistinguishable from the rest. Their setting is meant to re-rank the rule, not to erase what it observed. Pinning bands would
// pass just as well against an implementation that collapsed them, as long as it collapsed them to the value written down.
func TestApplyModifiers_OrderingSurvivesEveryOverride(t *testing.T) {
	t.Parallel()

	escalated := []RiskModifier{{Reason: "the domain reads as algorithmically generated", Risk: 25}}

	for _, base := range []string{SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical} {
		t.Run("base "+base, func(t *testing.T) {
			t.Parallel()
			plain := ApplyModifiers(base, nil)
			raised := ApplyModifiers(base, escalated)

			assert.GreaterOrEqual(t, RiskOf(raised), RiskOf(plain),
				"an escalated finding must never rank BELOW an ordinary one, whatever the rule was tuned to")
			if base != SeverityCritical {
				assert.Greater(t, RiskOf(raised), RiskOf(plain),
					"and must rank strictly above it, or the operator's tuning has erased the distinction rather than moved it")
			} else {
				// The one setting where they rank equally, and it is a statement about the scale rather than a gap in the fix:
				// an operator who set this rule to critical has said every finding from it is already as severe as the system
				// can express, so there is nothing above for an escalation to reach. The requirement says so in as many words.
				assert.Equal(t, SeverityCritical, raised, "there is nowhere above critical, so it stays there rather than overflowing")
			}
		})
	}
}

// TestApplyModifiers_UntunedRuleIsUnchanged pins the values the shipped rule reports today, which is the regression half: the
// composition is a change to how a severity is REACHED and must not be a change to what an untouched deployment sees.
func TestApplyModifiers_UntunedRuleIsUnchanged(t *testing.T) {
	t.Parallel()

	// dns_c2_beacon's own numbers: base high, and a DGA domain worth 25.
	dga := []RiskModifier{{Risk: 25}}
	assert.Equal(t, SeverityHigh, ApplyModifiers(SeverityHigh, nil), "an ordinary beacon stays high, as it always has")
	assert.Equal(t, SeverityCritical, ApplyModifiers(SeverityHigh, dga), "and a high-entropy domain still escalates to critical")

	// The case the issue names: lowered to low, the escalation survives as a smaller step rather than vanishing.
	assert.Equal(t, SeverityLow, ApplyModifiers(SeverityLow, nil))
	assert.Equal(t, SeverityMedium, ApplyModifiers(SeverityLow, dga),
		"a rule an operator lowered still ranks its escalated findings above its ordinary ones")
}

// TestApplyModifiers_IsIdentityWithNoModifiers pins that a finding carrying no escalation passes through untouched.
//
// Most findings carry none, and the engine calls this for all of them, so this is the common path rather than an edge. Without
// it a severity this package does not recognise would be quietly rewritten as medium: application_control_block copies a
// severity out of the agent's payload without validating it, and the alerts column's enum refuses a bad one loudly. Rewriting it
// here would turn that refusal into a plausible-looking alert, which is worse than the rejection it replaced.
func TestApplyModifiers_IsIdentityWithNoModifiers(t *testing.T) {
	t.Parallel()

	for _, band := range []string{SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical} {
		assert.Equal(t, band, ApplyModifiers(band, nil))
	}
	assert.Equal(t, "not-a-severity", ApplyModifiers("not-a-severity", nil),
		"an unrecognised severity must reach the store as it arrived, so the column can refuse it")
	assert.Empty(t, ApplyModifiers("", nil), "and so must an empty one")
}

// TestApplyModifiers_Clamps pins both ends of the scale, since a modifier is a delta and nothing stops a rule stacking several or
// declaring a negative one.
func TestApplyModifiers_Clamps(t *testing.T) {
	t.Parallel()

	assert.Equal(t, SeverityCritical, ApplyModifiers(SeverityCritical, []RiskModifier{{Risk: 1000}}),
		"running off the top of the scale is still critical, not an out-of-band value")
	assert.Equal(t, SeverityLow, ApplyModifiers(SeverityLow, []RiskModifier{{Risk: -1000}}),
		"and off the bottom is still low")
}

// TestRiskAndSeverityRoundTrip pins the band boundaries, because they are the numbers every delta is judged against and a shift in
// one of them silently re-ranks every finding in the product.
func TestRiskAndSeverityRoundTrip(t *testing.T) {
	t.Parallel()

	cases := []struct {
		risk int
		want string
	}{
		{0, SeverityLow}, {21, SeverityLow},
		{22, SeverityMedium}, {47, SeverityMedium},
		{48, SeverityHigh}, {73, SeverityHigh},
		{74, SeverityCritical}, {100, SeverityCritical},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, SeverityOf(c.risk), "risk %d", c.risk)
	}

	for _, band := range []string{SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical} {
		assert.Equal(t, band, SeverityOf(RiskOf(band)), "every band's representative risk must land back in that band")
	}

	// An unrecognised band is a value nothing here defined, so it neither buries a finding nor promotes one.
	require.Equal(t, RiskOf(SeverityMedium), RiskOf("not-a-severity"))
}
