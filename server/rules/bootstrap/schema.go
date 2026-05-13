package bootstrap

// schemaStatements are the CREATE TABLE statements the rules context
// owns. Idempotent (IF NOT EXISTS); safe to re-run on a populated DB.
// No cross-context FKs.
//
// Phase 1 of the add-application-control change drops the legacy
// `policies` singleton table outright. The four-table application
// control schema (`app_control_policies`, `app_control_rules`,
// `host_groups`, `app_control_assignments`) lands in phase 2 of that
// change. Until then this slice is empty; the rules context owns no
// tables.
var schemaStatements = []string{}
