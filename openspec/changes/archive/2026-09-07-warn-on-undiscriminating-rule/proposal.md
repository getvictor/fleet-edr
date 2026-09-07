# Warn when a rule discriminates nothing

## Why

The last piece of #767. A rule that matches everything is the foot-gun the issue names: it fires on every event of its type, so it buries real detections in noise and costs evaluation time on every batch to tell you nothing.

It is not an error, and that distinction is the whole design. An operator writing a deliberately broad hunting rule is doing something legitimate, and refusing it would substitute our judgement for theirs on a question we cannot answer: whether they meant it. So it is reported, and stored.

## What "discriminates nothing" means, precisely

The interesting part is being exact rather than approximately alarming, because a warning that fires on rules an operator wrote deliberately gets ignored, and then it is worth nothing when it matters.

A pattern matches every value when it is all stars and nothing else. `*` compiles to two empty segments, one before the star and one after, and matching walks the first from the start and the last to the end with nothing in between, so every string satisfies it. `**` collapses to the same shape.

Two neighbouring shapes are NOT this, and getting them wrong in either direction is the failure mode:

- An EMPTY pattern compiles to ONE empty segment, and a single segment must account for every byte, so it matches only the empty string. That is the opposite of undiscriminating, and a predicate written as "every segment is empty" would wrongly include it.
- `*?*` has a middle segment holding one atom, so it requires at least one character. Narrow, but not nothing.

From there it composes the way matching does. A field test discriminates nothing when the values that decide it are all unrestrictive: any one of them for the default form, all of them for `|all`. A search discriminates nothing when some alternative's every field test does, because an alternative is satisfied when all its field tests are.

## What it does not cover, said plainly

A `|re` pattern. Deciding whether a regular expression matches every string is a question about the regexp engine, not about globs, and a predicate that quietly returned false for `.*` would be worse than one that does not claim to cover the case at all. The corpus uses `|re` rarely and the warning says nothing about those rules rather than reassuring anyone.

Field PRESENCE is also still required. `Image|endswith: '*'` matches every event that carries an `Image`, which for exec events is all of them, so the warning is worded as what it is rather than as a claim about every event ever.

## Shape

The predicate lives with the matcher, because it is a question about compiled rule structure and nothing else can answer it without a second parser. The offending search NAMES come back, not a boolean: an operator fixing this needs to know which search to look at, and a rule with six searches and one wildcard is a different problem from one that is wildcards throughout.
