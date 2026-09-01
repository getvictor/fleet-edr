# Credit the rule's author wherever a match is displayed

## Why

Issue #765. The vendored SigmaHQ corpus ships under the Detection Rule License, which requires the rule's author be credited in views that display matches. Sixty-six of those rules now register and evaluate (#763, #771, #772), and #764 made promoting one to alert a single operator action. The moment an operator promotes one, we display matches from someone else's detection with no credit anywhere near them.

Attribution today reaches exactly one surface: the rule documentation page at `/rules/<id>`, via the `origin` field on `GET /api/rules`. The alert list, the alert breadcrumb and the webhook delivery carry nothing. Those are the surfaces that display matches, so they are the ones the obligation actually attaches to, and the rule doc page is two navigations away from an alert.

A second gap makes the first harder to close well. Attribution is currently empty for a rule this project wrote, so "has an origin" and "is vendored" are the same question. A display surface built on that has to render the credit conditionally, and a surface that renders a credit only when it happens to be present is one upstream change away from displaying a match with none.

## What changes

Every rule names an origin. A rule that declares no upstream is credited to this project rather than left blank, so attribution is total and a display surface renders it unconditionally. A rule that declares an upstream but names nobody is credited to neither: claiming it as ours would credit the wrong party, which is the one outcome worse than admitting the author is unknown.

An alert records the attribution of the rule that raised it, at the moment it was raised. The engine stamps it from the rule; it is not a field a rule can populate, so a rule cannot forge, reassign or suppress its own credit.

Attribution is stored on the alert rather than joined from the catalog when the alert is displayed. A join fails open for this obligation: an alert whose rule has since left the catalog would render with no credit at all, and #766 (runtime-loaded rule packs) turns that from an upgrade-day edge case into routine. A stored value fails safe, since its worst case is naming the author who was credited when the match happened, which is also the historically accurate answer. This matches how `title`, `description` and `severity` are already handled.

The alert list and the alert breadcrumb display the credit as rendered text. Not a tooltip: a credit shown only on hover is not shown to a reader scanning the list, printing it, or using a screen reader that does not announce title attributes.

A rule's references are carried through to its documentation page, so the credit can be checked against what the rule was written from. References on a vendored rule are third-party content, so a reference is rendered as a link only when its scheme is `http` or `https`; anything else is rendered as inert text.

## Impact

One existing requirement is reversed. `register-the-vendored-sigma-corpus` specified that a rule this project authored "SHALL report no attribution rather than naming this project, so the field distinguishes rather than decorates". That reasoning held while the catalog page was the only consumer, where absence reads as "we wrote it". It does not survive contact with the alert view, where absence reads as "nobody is credited" and cannot be told apart from a value that failed to arrive. The two populations stay distinguishable by the value instead, which is what the surface was going to have to read anyway.

**Archive ordering.** This change MODIFIES a requirement that `register-the-vendored-sigma-corpus` ADDs and that has not been archived yet, so that change must be archived first or the modification has nothing to apply to.

`alerts` gains an `origin` column (migration 00012). No backfill: every imported rule ships in monitor mode, which resolves before persistence, so no alert row raised by a vendored rule exists to credit. Rows predating the migration were all raised by rules this project wrote and keep the empty default, which is why the display surfaces still tolerate an absent credit rather than requiring one.

`GET /api/alerts` gains an additive `origin` field and the rule documentation payload gains an additive `references` array. The webhook envelope gains an additive `origin`; `schema_version` is unchanged, since a consumer that does not read the field is unaffected by its presence.
