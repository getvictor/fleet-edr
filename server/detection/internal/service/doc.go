// Package service is the detection orchestrator: a single struct
// that composes graph.Query + mysql.Store + the UserExists closure
// into the public api.Service interface.
//
// service.go owns the Service implementation. The IngestHandler
// returned by Service.IngestHandler() wraps the intake.Handler so
// cmd/main can mount POST /api/events under endpoint.HostToken
// middleware separate from the operator's session-gated mount.
//
// PUT /api/alerts/{id} reaches Service.UpdateAlertStatus, which
// validates updated_by via UserExists before persisting; that
// check replaces the fk_alerts_updated_by FK dropped in phase 5.
package service
