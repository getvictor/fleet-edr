package operator

import (
	"testing"

	"github.com/fleetdm/edr/server/rules/api"
)

// FuzzWindowParsers covers both `days` parsers together, because they are the same policy stated twice and the risk is that they
// drift apart rather than that either mishandles a number.
//
// The value is caller-controlled and reaches strconv.Atoi, so the properties worth holding are about what a REJECTION means as
// much as about what an acceptance produces. An accepted window that is not positive would be handed to a store that computes a
// cutoff from it, and a cutoff derived from a zero or a negative silently describes a window nobody asked for; the handler's own
// clamp is a `min`, which narrows a value and cannot repair one.
//
// Rejection is not tested against a list of bad strings, which would only restate the parser. It is tested as an equivalence: for
// any input, the two parsers agree on whether it is a window and on which window it is. They are separate functions on purpose,
// since the two window types must not be interchangeable, and this is what keeps that separation from becoming a divergence.
func FuzzWindowParsers(f *testing.F) {
	for _, seed := range []string{"", "7", "0", "-1", "1.5", "30", "365", " 7", "7 ", "+7", "0x7", "٧", "9223372036854775808", "\x00"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		matchDays, matchOK := matchCountWindow(true, raw)
		evalDays, evalOK := evalStatsWindow(true, raw)

		if matchOK != evalOK {
			t.Fatalf("the two window parsers disagree on %q: match=%v eval=%v", raw, matchOK, evalOK)
		}
		if matchOK && int(matchDays) != int(evalDays) {
			t.Fatalf("the two window parsers accepted %q as different windows: match=%d eval=%d", raw, matchDays, evalDays)
		}
		if matchOK && matchDays < 1 {
			t.Fatalf("accepted %q as a window of %d; a non-positive window would produce a cutoff nobody asked for", raw, matchDays)
		}
		// BOTH, because the equivalence above only compares values on acceptance: a parser drifting to return (42, false) would
		// otherwise satisfy every check here while handing a caller a window it also said was invalid.
		if !matchOK && (matchDays != 0 || evalDays != 0) {
			t.Fatalf("rejected %q but returned match=%d eval=%d rather than the zero value", raw, matchDays, evalDays)
		}
	})
}

// FuzzWindowParsersDefaultOnAbsence pins the one case that is NOT about the string: an absent parameter is the default window,
// and only an absent one. A supplied value that happens to be empty is a malformed value, and inferring omission from it would
// answer a question the caller did not ask and label the answer with a window they never chose.
func FuzzWindowParsersDefaultOnAbsence(f *testing.F) {
	f.Add("")
	f.Add("7")
	f.Fuzz(func(t *testing.T, raw string) {
		matchDays, matchOK := matchCountWindow(false, raw)
		evalDays, evalOK := evalStatsWindow(false, raw)
		if !matchOK || !evalOK {
			t.Fatalf("an absent parameter must be the default, but %q was rejected", raw)
		}
		if matchDays != api.DefaultMatchCountWindow || evalDays != api.DefaultEvalStatsWindow {
			t.Fatalf("an absent parameter gave %d/%d rather than the defaults, for raw %q", matchDays, evalDays, raw)
		}
	})
}
