// Package eventid mints the event_id every agent-synthesised event carries.
//
// It exists because two agent components now need one: agent/reconcile emits synthetic exits and snapshot heartbeats, and
// agent/sensorevent emits capture-provider transitions. `schema/events.json` declares event_id as a uuid-format string and
// the server dedups on it, so the two must agree on the format; keeping one implementation is what makes that true by
// construction rather than by two copies staying in sync.
package eventid

import (
	"crypto/rand"
	"encoding/hex"
)

// RFC 4122 §4.4: force the version nibble to 4 and the variant bits to 10x, so the value is a well-formed v4 UUID rather
// than bare random hex. Named rather than inline because a bare 0x40 in a bit operation is exactly the unexplained
// constant the magic-number linter exists to catch.
const (
	v4VersionMask byte = 0x0f
	v4VersionBits byte = 0x40
	v4VariantMask byte = 0x3f
	v4VariantBits byte = 0x80

	// uuidTextLen is 32 hex digits plus the four hyphens.
	uuidTextLen = 36
)

// NewV4 returns a random version-4 UUID in canonical 8-4-4-4-12 form.
//
// The error is crypto/rand failing, which does not happen on a healthy host but is returned rather than swallowed: a
// caller that emitted an event with an empty or duplicated id would have it silently deduped away by the server, so
// failing loudly is the only way that stays visible.
func NewV4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & v4VersionMask) | v4VersionBits
	b[8] = (b[8] & v4VariantMask) | v4VariantBits
	out := make([]byte, uuidTextLen)
	hex.Encode(out[0:8], b[0:4])
	out[8] = '-'
	hex.Encode(out[9:13], b[4:6])
	out[13] = '-'
	hex.Encode(out[14:18], b[6:8])
	out[18] = '-'
	hex.Encode(out[19:23], b[8:10])
	out[23] = '-'
	hex.Encode(out[24:36], b[10:16])
	return string(out), nil
}
