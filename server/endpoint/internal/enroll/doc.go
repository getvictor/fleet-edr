// Package enroll serves POST /api/enroll: the agent's first contact
// with the server. Public, rate-limited per source IP, validates the
// configured enroll secret, then delegates to api.Service.Enroll for
// host-id minting + token generation + initial policy/command fan-out.
// Wire shape preserved exactly across the modular-monolith migration:
// the agent never sees a difference.
//
// Internal to the endpoint bounded context. Do not import from outside
// server/endpoint/.
package enroll
