// Package service implements endpoint/api.Service by composing the
// mysql.Store with the optional PolicyProvider + CommandInserter
// (supplied by cmd/main as adapters around the still-existing policy
// and store packages until phases 3 and 4 land). The HTTP handlers in
// endpoint/internal/{enroll,operator,middleware} call into this package
// for business logic; cross-context callers (e.g. ingest's host-id
// lookup) call into it through the public api.Service.
//
// Internal to the endpoint bounded context. Do not import from outside
// server/endpoint/.
package service
