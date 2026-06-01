package bootstrap

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestInstanceID pins that this process's OTel service.instance.id is a valid, non-empty UUID that stays the same across reads.
// Init feeds it into the telemetry resource once, so a stable value here means every span/metric the binary emits carries the
// same replica identifier for its whole lifetime.
func TestInstanceID(t *testing.T) {
	t.Run("spec:server-availability/replica-identity-is-observable-via-service-instance-id/the-service-instance-id-is-stable-for-the-process-lifetime", func(t *testing.T) {
		got := instanceID()
		require.NotEmpty(t, got)

		_, err := uuid.Parse(got)
		require.NoError(t, err, "service.instance.id should be a valid UUID")
		assert.Equal(t, got, instanceID(), "service.instance.id must be stable for the process lifetime")
	})
}
