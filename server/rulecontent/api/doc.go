// Package api is the published surface of the rulecontent bounded context (ADR-0021).
//
// rulecontent owns rule definitions as durable CONTENT: the corpus and its version, and in later changes its provenance,
// authoring lifecycle, and the validation that untrusted rule content needs. It does not evaluate anything.
//
// The relationship with `rules` is supplier and consumer: rulecontent produces rule definitions, rules consumes and evaluates
// them. Everything crossing that seam goes through this package, the way rules already consumes detection/api's GraphReader.
package api
