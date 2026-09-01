package catalog

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestCredentialKeychainDump_TechniquesMapping pins the MITRE ATT&CK mapping the rule reports. Procurement + ATT&CK-Navigator export
// rely on this list being stable; flagging here forces a deliberate choice if someone changes it.
func TestCredentialKeychainDump_TechniquesMapping(t *testing.T) {
	t.Parallel()
	r := &CredentialKeychainDump{}
	assert.Equal(t, []string{"T1555.001"}, r.Techniques())
}
