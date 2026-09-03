// Package bootstrap wires the rulecontent bounded context (ADR-0021): its schema, its store, and the corpus seed.
//
// It is the only package outside rulecontent/internal that constructs the context, mirroring how the other seven contexts are
// assembled. Consumers hold the api.Corpus this returns and know nothing else about it.
package bootstrap
