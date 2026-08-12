package catalog

import (
	"context"
	"errors"

	"github.com/fleetdm/edr/server/rules/api"
)

// pendingMiss accumulates the retryable materialization miss (api.ErrProcessNotYetMaterialized) a rule's per-event loop hit, so the
// loop can keep evaluating the rest of the batch instead of returning on the first miss.
//
// Bailing on the first miss is what issue #661 was: one permanently orphaned event masked every other event in the same batch. The
// demo corpus carries nine captured network_connect events whose fork/exec predate the capture, so their process rows never
// materialize. dns_c2_beacon raised the retryable sentinel on the first of them, aborted its own event loop, and never reached the
// woven beacon connect later in the same batch. The processor nacked and re-claimed every poll tick, but the orphan could never
// resolve, so the loop only advanced once that orphan aged out of its own grace window. By then the real beacon connect was itself
// past the grace measured from its ingest stamp, so when the rule finally reached it a still-uncommitted process row degraded to the
// silent skip and the alert was dropped for good.
//
// Continuing past a miss keeps every guarantee the sentinel was introduced for: the miss is still reported to the engine after the
// loop, so the processor still nacks and re-evaluates the batch, and alert dedup still makes the re-run idempotent. What changes is
// that a finding another event in the batch already produced is no longer thrown away, and an unresolvable event can no longer spend
// a resolvable event's grace window.
type pendingMiss struct{ err error }

// absorb classifies a per-event evaluation error. A retryable materialization miss is remembered (first one wins, so the reported
// error names the event that started the wait) and absorb returns nil, telling the caller to continue the batch. Any other error is
// a genuine failure (a store error, a malformed graph read) and is returned unchanged for the caller to propagate immediately: those
// are not per-event conditions and retrying the remaining events against a broken reader would just multiply the failure.
func (p *pendingMiss) absorb(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, api.ErrRetryBatch) {
		if p.err == nil {
			p.err = err
		}
		return nil
	}
	return err
}

// evalEachEvent runs a per-event evaluator over a batch and collects the non-nil findings. Shared by rules whose Evaluate is a plain
// per-event fan-out (privilege_launchd_plist_write, sudoers_tamper, ...) so the identical loop lives in one place instead of being
// copy-pasted per rule.
//
// It returns the findings it did collect ALONGSIDE any retryable materialization miss, per the api.Rule.Evaluate contract: the engine
// persists those findings and still treats the miss as a reason to retry the batch.
func evalEachEvent(
	ctx context.Context,
	events []api.Event,
	s api.GraphReader,
	eval func(context.Context, api.Event, api.GraphReader) (*api.Finding, error),
) ([]api.Finding, error) {
	var findings []api.Finding
	var miss pendingMiss
	for _, evt := range events {
		f, err := eval(ctx, evt, s)
		if fatal := miss.absorb(err); fatal != nil {
			return nil, fatal
		}
		if f != nil {
			findings = append(findings, *f)
		}
	}
	return findings, miss.err
}
