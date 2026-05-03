// Package operator serves the session-gated operator routes:
//
//	GET /api/hosts                       - list hosts with online status
//	GET /api/hosts/{host_id}/tree        - process-tree for a host
//	GET /api/hosts/{host_id}/processes/{pid} - process detail
//	GET /api/alerts                      - list alerts (filtered)
//	GET /api/alerts/{id}                 - alert detail + correlated event_ids
//	PUT /api/alerts/{id}                 - update alert status (audited)
//
// All six are wrapped in identity.Session + identity.CSRF middleware
// by cmd/main. PUT /api/alerts/{id} additionally calls
// identity.api.Service.UserExists via the UserExists closure to
// validate the actor before persisting -- this replaces the
// fk_alerts_updated_by FK that the bounded-context split dropped.
package operator
