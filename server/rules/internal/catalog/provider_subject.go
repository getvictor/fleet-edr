package catalog

// providerSubject builds the dedup subject for a process-less finding about a capture provider, bounding the part of it the
// agent controls.
//
// # Why a bound is needed
//
// alerts.subject is VARCHAR(255) and participates in the UNIQUE dedup key. The provider name arrives in an agent-supplied
// JSON payload and is never length-validated on the way in, so a long or malformed one produces a subject the column
// cannot hold. That failure does not stop at the one alert: a persistence error aborts the batch's evaluation, so it can
// take other rules' findings down with it and drive repeated retries.
//
// # Why the PROVIDER is what gets trimmed
//
// Truncating the finished subject would be worse than the bug it fixes. The event id sits at the end, and it is what makes
// one stop distinct from another; cutting it would collapse separate incidents onto one subject, and dedup would silently
// suppress real alerts. Trimming the provider instead cannot do that: the event id is already unique per event, so two
// different records keep different subjects however aggressively their provider names are shortened. The provider is
// carried in the subject for legibility, not for identity.
//
// Trimming by RUNE rather than byte, so a multi-byte name is never cut mid-character and turned into invalid UTF-8.
func providerSubject(prefix, provider, eventID string) string {
	if r := []rune(provider); len(r) > providerSubjectMaxRunes {
		provider = string(r[:providerSubjectMaxRunes])
	}
	return prefix + ":" + provider + ":" + eventID
}

// providerSubjectMaxRunes bounds the provider portion. Set well above any real provider name (the longest the extension
// reports is "content_filter") and low enough that the whole subject fits the column with room to spare: the longest prefix
// here is 22 characters and an event id is a 36-character UUID, so the worst case is around 124. A generous fixed cap keeps
// the arithmetic obvious, rather than deriving a remainder that would need revisiting whenever a prefix changed.
const providerSubjectMaxRunes = 64
