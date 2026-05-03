// Package sqlhelpers holds small SQL plumbing types that more than one
// bounded context needs. The first inhabitant is NullRawJSON: a
// json.RawMessage that round-trips correctly through database/sql for
// MySQL JSON columns that are nullable.
//
// Bounded contexts that have schema columns of nullable JSON shape
// (detection's processes.args / processes.code_signing,
// response's commands.result) all import this package rather than each
// shipping a private copy. Keeping the canonical type here avoids
// drift between the two implementations and lets tests live in one
// place.
//
// This package must NOT import any bounded-context package; it sits
// at the same platform tier as server/bootstrap and server/httpserver.
package sqlhelpers
