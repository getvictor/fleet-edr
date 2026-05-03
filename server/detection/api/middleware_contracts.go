// This file is reserved for future middleware contracts that
// detection's api package may need to expose (e.g. context-key
// constants, request scoping helpers).
//
// detection has no middleware of its own: the agent ingest path is
// gated by endpoint.HostToken upstream, the operator read path by
// identity.Session upstream. Reserved file kept for layout
// consistency with other contexts.

package api
