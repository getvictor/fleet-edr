package fakeagent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// schemaPath is schema/events.json relative to this package. The document is the wire contract every emitter in the repo mirrors by
// hand (this package, test/e2e/fixtures/agent.ts, and the extension's Swift payload structs), so the tests below are the only thing
// that observes drift between the contract and what we actually put on the wire.
const schemaPath = "../../schema/events.json"

// compileEnvelopeSchema compiles schema/events.json. Instances must be decoded with jsonschema.UnmarshalJSON rather than
// encoding/json so integer keywords see json.Number instead of float64.
func compileEnvelopeSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	raw, err := os.ReadFile(schemaPath)
	require.NoError(t, err)
	doc, err := jsonschema.UnmarshalJSON(strings.NewReader(string(raw)))
	require.NoError(t, err)
	c := jsonschema.NewCompiler()
	require.NoError(t, c.AddResource("events.json", doc))
	sch, err := c.Compile("events.json")
	require.NoError(t, err)
	return sch
}

// validateEnvelope runs one envelope, given as marshalled JSON, through the compiled schema.
func validateEnvelope(t *testing.T, sch *jsonschema.Schema, envelope []byte) error {
	t.Helper()
	inst, err := jsonschema.UnmarshalJSON(strings.NewReader(string(envelope)))
	require.NoError(t, err)
	return sch.Validate(inst)
}

// envelopeJSON wraps a payload in the five envelope fields the schema requires.
func envelopeJSON(t *testing.T, eventType, payload string) []byte {
	t.Helper()
	return []byte(`{"event_id":"6f1a3a1e-9c4a-4a5e-9b3f-2c0d5e8a7b61","host_id":"host-1","timestamp_ns":1750000000000000000,` +
		`"event_type":"` + eventType + `","payload":` + payload + `}`)
}

// payloadFixtures carries one minimally-valid payload per event_type. TestEventSchema_EveryEventTypeValidates asserts the key set
// equals the schema's event_type enum, so a new event type without a fixture fails rather than going unexercised.
var payloadFixtures = map[string]string{
	"exec":                       `{"pid":100,"ppid":1,"path":"/bin/zsh","args":["zsh","-c","id"],"cwd":"/","uid":501,"gid":20}`,
	"fork":                       `{"child_pid":101,"parent_pid":100}`,
	"exit":                       `{"pid":101,"exit_code":0}`,
	"open":                       `{"pid":101,"path":"/etc/sudoers","flags":1}`,
	"file_rename":                `{"pid":101,"source_path":"/tmp/staged","path":"/etc/sudoers"}`,
	"file_truncate":              `{"pid":101,"path":"/etc/sudoers"}`,
	"file_delete":                `{"pid":101,"path":"/etc/sudoers.d/admins"}`,
	"network_connect":            `{"pid":101,"protocol":"tcp","direction":"outbound","remote_address":"93.184.216.34","remote_port":443}`,
	"dns_query":                  `{"pid":101,"query_name":"example.com","query_type":"A"}`,
	"snapshot_heartbeat":         `{"pid":101}`,
	"btm_launch_item_add":        `{"item_type":"agent","item_path":"/Library/LaunchAgents/com.example.plist"}`,
	"sensor_provider_transition": `{"provider":"network_extension","state":"stopped"}`,
	"sensor_recovery_failed":     `{"provider":"network_extension","outcome":"attempts_exhausted","attempts":3}`,
	"application_control_block": `{"pid":101,"path":"/tmp/tool","rule_id":"r-1","rule_type":"CDHASH","identifier":"abc",` +
		`"severity":"high","policy_id":1,"policy_version":2}`,
	"application_control_undecided": `{"pid":101,"path":"/tmp/tool","verdict":"allow","reason":"deadline",` +
		`"file_size_bytes":4096,"policy_id":1,"policy_version":2}`,
	"application_control_resync": `{"policy_id":1,"previous_version":5,"new_version":2,"previous_epoch":1,"new_epoch":2,` +
		`"reason":"version_regression"}`,
}

// TestEventSchema_EveryEventTypeValidates is the regression test for issue #937. Under the previous `payload.oneOf` the schema
// required EXACTLY ONE payload definition to match, and no definition set additionalProperties: false, so every payload carrying a
// pid also satisfied snapshot_heartbeat_payload (whose sole requirement is pid). Ten of the sixteen event types matched two
// definitions and therefore failed. Measured against that schema, ten of these subtests fail and six pass: fork, snapshot_heartbeat,
// btm_launch_item_add, application_control_resync and the two sensor payloads carry no pid, so they matched exactly one definition
// and validated even then.
//
// spec:endpoint-event-collection/event-payload-schema-is-selected-by-event-type/each-documented-event-type-validates
func TestEventSchema_EveryEventTypeValidates(t *testing.T) {
	t.Parallel()
	sch := compileEnvelopeSchema(t)

	require.ElementsMatch(t, schemaEventTypes(t), mapKeys(payloadFixtures),
		"payloadFixtures must carry exactly one fixture per event_type in the schema enum")

	for eventType, payload := range payloadFixtures {
		t.Run(eventType, func(t *testing.T) {
			t.Parallel()
			assert.NoError(t, validateEnvelope(t, sch, envelopeJSON(t, eventType, payload)))
		})
	}
}

// TestEventSchema_PayloadMismatchedToEventTypeIsRejected covers the other half of the discriminator: the payload is checked against
// the definition its own event_type selects, so a body belonging to a different event type is refused.
//
// spec:endpoint-event-collection/event-payload-schema-is-selected-by-event-type/a-mismatched-payload-is-rejected
func TestEventSchema_PayloadMismatchedToEventTypeIsRejected(t *testing.T) {
	t.Parallel()
	sch := compileEnvelopeSchema(t)

	cases := []struct {
		name      string
		eventType string
		payload   string
		want      string
	}{
		{
			// The exact shape the old oneOf accepted for every pid-carrying type. It must now be refused for anything but a
			// heartbeat, which is what made the previous schema vacuous.
			name:      "heartbeat body under exec",
			eventType: "exec",
			payload:   `{"pid":101}`,
			want:      "ppid",
		},
		{
			name:      "open body missing flags",
			eventType: "open",
			payload:   `{"pid":101,"path":"/etc/sudoers"}`,
			want:      "flags",
		},
		{
			name:      "exec body under network_connect",
			eventType: "network_connect",
			payload:   payloadFixtures["exec"],
			want:      "protocol",
		},
		{
			name:      "rename body missing its source",
			eventType: "file_rename",
			payload:   `{"pid":101,"path":"/etc/sudoers"}`,
			want:      "source_path",
		},
		{
			name:      "resync body with an unlisted reason",
			eventType: "application_control_resync",
			payload:   `{"policy_id":1,"previous_version":5,"new_version":2,"previous_epoch":1,"new_epoch":2,"reason":"operator"}`,
			want:      "reason",
		},
		{
			name:      "block body with a string pid",
			eventType: "application_control_block",
			payload: `{"pid":"101","path":"/tmp/t","rule_id":"r","rule_type":"CDHASH","identifier":"a","severity":"high",` +
				`"policy_id":1,"policy_version":2}`,
			want: "pid",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := validateEnvelope(t, sch, envelopeJSON(t, tc.eventType, tc.payload))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

// TestEventSchema_UndeclaredPayloadFieldIsAccepted pins the deliberate decision NOT to set additionalProperties: false on the
// payload definitions. With event_type doing the discrimination, forbidding extra keys would buy no correctness, and it would make
// the document stricter than the ingest path, which tolerates unknown fields. Without this test, adding additionalProperties: false
// would pass the rest of the suite while contradicting the requirement, because every other fixture carries only declared fields.
//
// spec:endpoint-event-collection/event-payload-schema-is-selected-by-event-type/a-payload-carrying-an-undeclared-field-is-accepted
func TestEventSchema_UndeclaredPayloadFieldIsAccepted(t *testing.T) {
	t.Parallel()
	sch := compileEnvelopeSchema(t)

	// An exec payload plus a field no definition declares, standing in for a wire field added ahead of the document.
	payload := `{"pid":100,"ppid":1,"path":"/bin/zsh","args":["zsh"],"cwd":"/","uid":501,"gid":20,"undeclared_field":"x"}`
	assert.NoError(t, validateEnvelope(t, sch, envelopeJSON(t, "exec", payload)))
}

// TestEventSchema_ShippedScenarioEnvelopesValidate runs the envelopes this package actually emits through the schema. The fixtures
// above pin the contract; this pins the emitter to it, which is the half that catches drift introduced by a change to buildPayload
// rather than to the schema.
//
// spec:endpoint-event-collection/event-payload-schema-is-selected-by-event-type/emitted-envelopes-validate-against-the-document
func TestEventSchema_ShippedScenarioEnvelopesValidate(t *testing.T) {
	t.Parallel()
	sch := compileEnvelopeSchema(t)

	entries, err := os.ReadDir("scenarios")
	require.NoError(t, err)
	require.NotEmpty(t, entries)

	seen := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".yaml" {
			continue
		}
		s, err := LoadScenario(filepath.Join("scenarios", e.Name()))
		require.NoError(t, err)
		envelopes, err := s.Envelopes()
		require.NoError(t, err)
		require.NotEmpty(t, envelopes, "%s produced no envelopes", e.Name())

		for i, env := range envelopes {
			raw, err := json.Marshal(env)
			require.NoError(t, err)
			assert.NoErrorf(t, validateEnvelope(t, sch, raw), "%s timeline[%d] (%s)", e.Name(), i, env.EventType)
			seen[env.EventType] = true
		}
	}
	// The corpus is the evidence, so record what it actually reached: an assertion that it covers every type would fail on the
	// three application_control_* types, which the agent emits reactively and no scenario produces.
	t.Logf("scenario corpus exercised %d event types: %v", len(seen), sortedKeys(seen))
	assert.Greater(t, len(seen), 5, "scenario corpus should exercise more than a handful of event types")
}

// TestEventSchema_DiscriminatorCoversEveryEventType guards the structure itself: every value in the event_type enum has an if/then
// clause pointing at an existing <event_type>_payload definition, and no clause names a type outside the enum. Without this, adding
// an event type without its clause leaves that type's payload completely unconstrained and nothing else notices.
//
// spec:endpoint-event-collection/event-payload-schema-is-selected-by-event-type/every-event-type-has-a-discriminator-clause
func TestEventSchema_DiscriminatorCoversEveryEventType(t *testing.T) {
	t.Parallel()
	doc := rawSchema(t)

	definitions, ok := doc["definitions"].(map[string]any)
	require.True(t, ok)

	allOf, ok := doc["allOf"].([]any)
	require.True(t, ok, "schema must discriminate the payload with a top-level allOf")

	clauseTypes := make([]string, 0, len(allOf))
	for i, entry := range allOf {
		clause, ok := entry.(map[string]any)
		require.Truef(t, ok, "allOf[%d]", i)

		ifPart, ok := clause["if"].(map[string]any)
		require.Truef(t, ok, "allOf[%d].if", i)
		// Without "required": ["event_type"] the if matches vacuously on an envelope that omits event_type, applying every
		// then at once and reporting a payload error instead of the missing discriminator.
		assert.Equalf(t, []any{"event_type"}, ifPart["required"], "allOf[%d].if must require event_type", i)
		eventType := digString(t, ifPart, "properties", "event_type", "const")
		clauseTypes = append(clauseTypes, eventType)

		thenPart, ok := clause["then"].(map[string]any)
		require.Truef(t, ok, "allOf[%d].then", i)
		ref := digString(t, thenPart, "properties", "payload", "$ref")
		assert.Equalf(t, "#/definitions/"+eventType+"_payload", ref, "allOf[%d].then payload ref", i)
		assert.Containsf(t, definitions, eventType+"_payload", "allOf[%d] refers to a missing definition", i)
	}

	assert.ElementsMatch(t, schemaEventTypes(t), clauseTypes,
		"every event_type needs exactly one if/then clause and vice versa")

	payload, ok := doc["properties"].(map[string]any)["payload"].(map[string]any)
	require.True(t, ok)
	// oneOf required exactly one definition to match, which no pid-carrying payload could satisfy while
	// snapshot_heartbeat_payload accepted any object with a pid.
	assert.NotContains(t, payload, "oneOf", "payload must be selected by event_type, not by matching exactly one definition")
}

func rawSchema(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(schemaPath)
	require.NoError(t, err)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(raw, &doc))
	return doc
}

func schemaEventTypes(t *testing.T) []string {
	t.Helper()
	doc := rawSchema(t)
	properties, ok := doc["properties"].(map[string]any)
	require.True(t, ok)
	eventType, ok := properties["event_type"].(map[string]any)
	require.True(t, ok)
	values, ok := eventType["enum"].([]any)
	require.True(t, ok)
	require.NotEmpty(t, values)

	out := make([]string, 0, len(values))
	for _, v := range values {
		s, ok := v.(string)
		require.True(t, ok)
		out = append(out, s)
	}
	return out
}

// digString walks a nested JSON object and returns the string at the end of the path, failing the test if any hop is absent.
func digString(t *testing.T, node map[string]any, path ...string) string {
	t.Helper()
	for i, key := range path {
		value, ok := node[key]
		require.Truef(t, ok, "missing %q in %v", key, path[:i])
		if i == len(path)-1 {
			s, ok := value.(string)
			require.Truef(t, ok, "%v is not a string", path)
			return s
		}
		node, ok = value.(map[string]any)
		require.Truef(t, ok, "%v is not an object", path[:i+1])
	}
	return ""
}

func mapKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
