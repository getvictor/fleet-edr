// Package service implements endpoint/api.Service by composing the
// mysql.Store with the signed-token Signer and the revocation snapshot.
// The HTTP handlers in endpoint/internal/{enroll,operator,middleware,token}
// call into this package for business logic; cross-context callers (e.g.
// ingest's host-id lookup) call into it through the public api.Service.
//
// Internal to the endpoint bounded context. Do not import from outside
// server/endpoint/.
package service
