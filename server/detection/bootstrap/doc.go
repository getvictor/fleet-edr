// Package bootstrap wires the detection bounded context. cmd/* binaries
// call detectionbootstrap.New(deps) once at startup, then ApplySchema,
// then MigrateSchema, then RegisterIngestRoutes / RegisterAuthedRoutes /
// RegisterHealthRoutes (full mode) or just RegisterIngestRoutes (intake
// mode), and finally `go detectionCtx.Run(ctx)` to fan out the
// processor + processttl + retention goroutines.
//
// The handle exposes:
//   - Service() api.Service for cross-context callers (response uses
//     RecordHostSeen as its Heartbeat closure target).
//   - LoadActive(rulesapi.RuleProvider) to register the active rule
//     set with the engine after rulesCtx exists.
//
// ActiveHostsLister and CommandInserter are unrelated to detection;
// detection's only outbound closure is UserExists, which cmd/main
// supplies from identity.api.Service.UserExists. UserExists replaces
// the cross-context FK fk_alerts_updated_by that the bounded-context
// migration dropped.
package bootstrap
