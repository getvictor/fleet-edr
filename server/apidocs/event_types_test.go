package apidocs

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

// eventSchemaPath is the event wire schema of record, relative to this package's directory.
const eventSchemaPath = "../../schema/events.json"

// spec:endpoint-event-collection/canonical-event-envelope/published-copies-of-the-event-type-list-agree
//
// TestEventEnvelopeListsEveryEventType keeps the ingest request schema's event_type enum equal to the event schema's.
//
// The two are maintained by hand in different formats, and the OpenAPI copy was missing eight types when this test was written:
// a client validating its request against the published spec would have refused events the server accepts.
func TestEventEnvelopeListsEveryEventType(t *testing.T) {
	t.Parallel()

	rawSchema, err := os.ReadFile(eventSchemaPath)
	require.NoError(t, err)
	var schema struct {
		Properties struct {
			EventType struct {
				Enum []string `json:"enum"`
			} `json:"event_type"`
		} `json:"properties"`
	}
	require.NoError(t, json.Unmarshal(rawSchema, &schema))
	require.NotEmpty(t, schema.Properties.EventType.Enum, "an empty event schema enum would make this test compare nothing")

	rawSpec, err := os.ReadFile(canonicalSpecPath)
	require.NoError(t, err)
	var spec struct {
		Components struct {
			Schemas struct {
				EventEnvelope struct {
					Properties struct {
						EventType struct {
							Enum []string `yaml:"enum"`
						} `yaml:"event_type"`
					} `yaml:"properties"`
				} `yaml:"EventEnvelope"`
			} `yaml:"schemas"`
		} `yaml:"components"`
	}
	require.NoError(t, yaml.Unmarshal(rawSpec, &spec))

	assert.Equal(t, schema.Properties.EventType.Enum, spec.Components.Schemas.EventEnvelope.Properties.EventType.Enum,
		"docs/api/openapi.yaml's EventEnvelope.event_type enum must list schema/events.json's event types, in the same order")
}
