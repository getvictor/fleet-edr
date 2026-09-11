# Name and group ATT&CK techniques from the published data

## Why

The coverage page rendered 53 of its 65 techniques as "Unmapped", with the bare technique id where the name should be, because the catalog it read from was a hand-written list of 12 that nobody had kept up. Its own comment called the fallback "a loud-but-not-broken hint that this file needs an update"; nothing failed while it went 53 short. The tactic vocabulary was stale too, still naming Defense Evasion, which ATT&CK v19 replaced with Stealth and Defense Impairment.

The mapping cannot be derived from our own rules. Sigma tags tactics at the rule level and mixes them into one namespace with technique and software ids, so a rule carrying `attack.persistence`, `attack.t1543.004` and `attack.s0402` says what the rule relates to, not what that technique belongs to. Measured on this corpus, 38 of 61 techniques got conflicting answers that way. Technique-to-tactic is a fact about ATT&CK, so it comes from ATT&CK.

## What changes

The page reads a table generated from MITRE's published ATT&CK release, so every technique a rule covers renders with its real name under its real tactics. Two consequences worth stating as behaviour rather than leaving implicit:

- A technique appears under **every** tactic ATT&CK gives it, not just the first. T1543.004 is Persistence and Privilege Escalation; listing it under one made the other look uncovered when a rule covers it. The upstream Navigator repeats a technique the same way.
- The count of techniques covered only by silent rules gains a link to Detection tuning, shown only to operators who can reach that page. The coverage page itself is open to everyone, so an ungated link would send some operators to a no-access page.

## Impact

- `ui/src/components/AttackCoverage.tsx`, and a generated `attack-techniques.generated.ts` replacing the hand-written catalog
- `tools/attacktable` generates the table; `task attack:latest-check` is a release-checklist step
- No server, API, or persistence change: the same endpoint returns the same layer document
