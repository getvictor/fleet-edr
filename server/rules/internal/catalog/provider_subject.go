package catalog

import (
	"crypto/sha256"
	"encoding/hex"
)

// providerSubject builds the dedup subject for a process-less finding about a capture provider, bounded so it always fits
// its column whatever the agent sent.
//
// # Why a bound is needed
//
// alerts.subject is VARCHAR(255) and participates in the UNIQUE dedup key, and BOTH halves of the subject are
// agent-supplied and unvalidated: the provider comes from an event payload, and event_id is itself a VARCHAR(255) that
// ingest never length-checks or parses as a UUID. A subject the column cannot hold fails the INSERT, and that failure does
// not stop at the one alert: a persistence error aborts the batch's evaluation, so it can take other rules' findings down
// with it and drive repeated retries.
//
// # Two bounds, because the two halves are not interchangeable
//
// The provider is trimmed first, by rune so a multi-byte name is never cut into invalid UTF-8. That alone would be enough
// if event ids were the 36-character UUIDs the agent actually emits, and an earlier version of this stopped there. It is
// not enough in general: nothing prevents a near-255-character event_id, which overflows the budget however short the
// provider is.
//
// So the finished subject is length-checked too, and when it still does not fit it collapses to a hash of itself. That
// keeps the property dedup depends on, which is that the subject is a FUNCTION of (provider, event id): the same record
// always produces the same subject, and two different records produce different ones. The readable form is preferred
// whenever it fits, because a hashed subject is opaque when someone is reading rows by hand; the provider is named in the
// finding's description either way, so nothing an operator reads is lost.
//
// Truncating the finished subject instead would be the obvious move and is wrong. The event id sits at the end and is what
// makes one record distinct from another, so cutting it would collapse separate incidents onto one subject and dedup would
// then silently suppress real alerts, which is a worse failure than the oversized insert this prevents.
func providerSubject(prefix, provider, eventID string) string {
	if r := []rune(provider); len(r) > providerSubjectMaxRunes {
		provider = string(r[:providerSubjectMaxRunes])
	}
	subject := prefix + ":" + provider + ":" + eventID
	if len(subject) <= subjectMaxBytes {
		return subject
	}
	sum := sha256.Sum256([]byte(subject))
	return prefix + ":" + hex.EncodeToString(sum[:])
}

// providerSubjectMaxRunes bounds the provider portion of a readable subject. Set well above any real provider name (the
// longest the extension reports is "content_filter") so the trim is invisible in practice.
const providerSubjectMaxRunes = 64

// subjectMaxBytes mirrors alerts.subject VARCHAR(255). Measured in BYTES rather than characters, which is the conservative
// reading: MySQL counts that column in characters, so anything within the byte budget is necessarily within the character
// one. The hashed fallback is far shorter than either (the longest prefix here is 22, plus a colon and 64 hex characters),
// so the bound holds with a wide margin rather than by exact arithmetic.
const subjectMaxBytes = 255
