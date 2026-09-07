# Give operators an authoring surface, and make every change attributable

## Why

#873 built the write path and the validation that guards it, and nothing calls either. This is the consumer half: the HTTP surface an operator reaches, the authorization that decides who may reach it, and the audit trail that records what they did.

The audit half is the remaining acceptance criterion of #767 ("every create and edit is attributable to an actor"), and it is the one that matters most here. Rule content decides what a fleet detects. A change to it that nobody can attribute is worse than a change to a tuning setting nobody can attribute, because the tuning surface already records its mutations and this one would be the gap.

## Where it lives, and why that is not `rulecontent`

ADR-0021 deferred one question to #767: whether the operator-facing HTTP surface for authoring lives in `rulecontent` or in the `rules` operator handler. #873's proposal answered it and this change implements the answer: the `rules` operator handler.

The reason is that authoring shares everything the tuning surface already has. The same authorization chokepoint, the same audit recorder, the same handler shell and error vocabulary, and the same screen: an operator authors a rule and then sets its mode from the table next to it. Putting the HTTP surface in `rulecontent` would mean a second operator handler, a second authz wiring, and a duplicate of the audit plumbing, to serve a page that sits beside one that already exists.

The content half stays where the ADR put it. `rulecontent` owns the documents, their version, the write transaction, and the validate-then-write ordering; what crosses into `rules` is the HTTP surface, and it crosses by holding `rulecontent/api`'s published lifecycle rather than by reaching inside.

## Audit records what happened, not what was attempted

Only a change that took effect is recorded as a mutation. A submission the validator refused did not change the corpus, and recording it as though it did would make the audit trail disagree with the thing it audits.

That is not the same as saying refusals are invisible: the chokepoint already records an authorization denial, and a refusal is returned to the operator with the validator's reason. What is not recorded is a *mutation* that did not occur.

## Authorization mirrors the tuning surface

Read is held by admin and senior_analyst; write by admin. That is what `detection_config` does, and authoring belongs in the same band: it is a governed change to what the deployment detects, made by the same people, from the same screen. A narrower band would be defensible for a surface that could break detection outright, but validation is what stops that, and it runs before anything is stored.

## Not here

The warning for a detection with no discriminating predicate. It needs a predicate over compiled rule structure that does not exist yet, which is a different kind of work from wiring a surface, and bundling them would put both past the size this repository aims for.
