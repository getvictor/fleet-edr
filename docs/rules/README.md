# Rule pack

The pack moved. One declarative rule file per registered detection now lives at [`server/rules/internal/catalog/pack/`](../../server/rules/internal/catalog/pack), inside the package that reads it.

## Why it moved

Phase 1 generated these files and nothing read them, so `docs/` was a reasonable home. From Phase 2 the rules read their own parameters out of them at boot, and a `go:embed` pattern cannot contain `..`, so a package under `server/rules/` cannot embed a directory at the repository root.

Keeping the canonical copy here and generating a second one next to the code was the obvious workaround and the wrong one: that is the arrangement in issue #781, where the embedded OpenAPI spec drifted 49 lines from its canonical source because the `go:generate` that syncs them is wired to nothing. One canonical location, owned by the code that reads it, has no such failure mode.

## Working with the pack

Refresh it with `task docs:rule-pack`. A stale or missing file fails CI, and regeneration removes files for rules that are no longer registered.

Everything in a rule file is generated from the rule's Go documentation **except `x-engine.params`**, which the rules read at boot and which is therefore authored by hand. Regeneration re-emits an existing params block verbatim, comments included.

## Where a value lives

What reads a value decides which file holds it.

A value only one rule matches against is that rule's parameter, under `x-engine.params` in its own file. A value more than one rule matches against lives in `pack/lists.yml`, defined once and read by every consumer; copying it into each rule's file would leave nothing keeping the copies equal, which is weaker than the single definition it replaced. `lists.yml` is authored rather than generated, and regeneration leaves it alone.

Some values stay in Go on purpose. A parameter that bounds **retrieval** rather than the decision (the ingest and clock-skew pads, the ancestor-walk and descendant caps, the DNS port) is not exposed, because widening it changes no finding and narrowing it causes silent false negatives: no setting improves detection, so the knob would be all downside.

## Reading rules in the console

Operators with `rule_content.read` have a **Rules** entry in the top navigation. It lists every rule the deployment runs with its severity, the mode it runs in (marked when an operator set it), and whether it shipped with the product or was written on this deployment. A rule's page shows the rule document it is loaded from, exactly as stored. Rules built into the server are not loaded from a stored document, and their page says so.

Operators with `rule_content.write` can also change rules there. **New rule** opens an editor: pick an identifier, edit the document, and **Check** it, which asks the server whether the document is valid and shows the loader's reason if not. Saving also checks it against the deployment's other rules, so a clash such as an identifier already in use is refused then. **Save** needs a passing check of what is on screen and a reason for the audit log. A saved change takes effect when the server next reloads its rules, within 30 seconds. A new rule runs in monitor mode until you promote it in Detection tuning. A rule you wrote has **Edit** and **Delete** on its page; shipped rules are tuned in Detection tuning instead. The catalogue also reports whether the deployment runs the shipped rules this build carries, and can roll back to the previous set.

## Rule identifiers

A rule's identifier is its **file stem**: `keychain_dump.yml` defines the rule `keychain_dump`. The identifier is not written inside the file, so renaming the file renames the rule, and everything keyed by it (per-rule mode and severity overrides, alert deduplication, exclusions) follows the new name rather than the old one.

These constraints apply, and a corpus that breaks any of them is refused as a whole rather than partially loaded.

**Letters, digits, underscore and hyphen only.** Not because anything else is hard to parse, but because identifiers are stored in columns whose collation is case- and accent-insensitive. Over a wider character set, `naive_rule` and `naïve_rule` are one identifier to the database and two to the corpus, and there is no comparison that can be written here that reliably agrees with the database's. Narrowing the character set makes the question decidable instead.

**At most 255 characters,** which is the width of every column that stores one.

**Not already used by a rule the product ships.** Stored rules are added to the ones built into the server, and nothing downstream tells the two apart, so a stored `suspicious_exec.yml` would produce two rules that share one set of per-rule settings and one alert deduplication key.

**Unique ignoring case.** `Keychain_Dump.yml` and `keychain_dump.yml` are the same rule as far as per-rule settings and alert deduplication are concerned, so a corpus carrying both would show two rules that cannot be tuned or triaged separately. Storage itself is case-sensitive, which is what lets both files exist; the refusal is what stops them being loaded together.

## What else a corpus must satisfy

- **Every file is `.yml`.** The loader reads nothing else, so a rule stored under another extension would be kept, reported as stored, and never evaluated.
- **Paths are plain and relative, and none sits under another.** No leading slash, and no `.` or `..` segments. A rule may not be nested beneath another rule's path either: `authored/a.yml/nested.yml` stores happily but the loader treats `a.yml` as a file and never looks inside it. Two paths that differ only by a leading slash are distinct rows in storage but the same file to the loader, so one of the two would silently disappear at load.
- **At least one rule must run.** A corpus in which nothing loads is refused, including an empty one. An empty corpus does not mean "no rules": the server keeps the rule set already in force when it finds nothing to load, so the rules an operator meant to remove would go on running.
- **Bounded size.** A rule file may be up to 64 KiB, its path up to 255 characters, and a corpus up to 4096 rules. The whole corpus is revalidated on every edit and reparsed by every replica whenever it changes, so these bound work that is otherwise unbounded. The largest rule shipped here is under 4 KiB.
