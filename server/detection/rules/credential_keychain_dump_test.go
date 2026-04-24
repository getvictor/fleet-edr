package rules

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/fleetdm/edr/server/detection/testharness"
)

// TestCredentialKeychainDump_Fixtures runs every fixture case under
// fixtures/credential_keychain_dump/ as its own sub-test. Add a new
// case by dropping a *.json file in that directory — no Go edits
// needed. See server/detection/testharness for the fixture schema.
func TestCredentialKeychainDump_Fixtures(t *testing.T) {
	testharness.Replay(t, &CredentialKeychainDump{}, "fixtures/credential_keychain_dump")
}

// TestCredentialKeychainDump_TechniquesMapping pins the MITRE ATT&CK
// mapping the rule reports. Procurement + ATT&CK-Navigator export
// rely on this list being stable; flagging here forces a deliberate
// choice if someone changes it.
func TestCredentialKeychainDump_TechniquesMapping(t *testing.T) {
	r := &CredentialKeychainDump{}
	assert.Equal(t, []string{"T1555.001"}, r.Techniques())
}
