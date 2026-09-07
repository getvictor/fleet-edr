# Tasks

## 1. Correct the mappings that were not earned

- [x] 1.1 Drop Spearphishing Attachment from the Office rule, keeping the phishing context in the description.
- [x] 1.2 Drop Ingress Tool Transfer from both shell-chain rules, neither of which observes anything arriving.
- [x] 1.3 Move both from the parent interpreter technique to the Unix Shell sub-technique, which each matches by path.
- [x] 1.4 Resolve the drift where a type comment named User Execution while the code declared Ingress Tool Transfer: drop both rather than pick a survivor, since neither is observed.

## 2. Decide the arguable ones explicitly

- [x] 2.1 Drop the sensor-tamper mapping. A technique names either a behaviour or an actor's action, and Impair Defenses is the second; the rule observes a state a crash produces identically. Record what would re-earn it.
- [x] 2.2 Drop the AppleScript dropper's transfer mapping. The descendant check matches a downloader by path and inspects nothing else, so a downloader running is what is observed and the transfer is inferred.
- [x] 2.3 Keep severity and title identical throughout, and take the attribution out of the two alert TEXTS that carried one in prose.

## 3. Make the mapping hard to change by accident

- [x] 3.1 Pin the whole first-party mapping as one exact set, with the observation that earns each entry.
- [x] 3.2 Assert no rule declares both a parent technique and its own sub-technique, which the exact set alone cannot express.
- [x] 3.3 Regenerate the rule reference, the Navigator layer and the rule pack, and read the coverage diff as the deliberate change it is.
- [x] 3.4 Rename the L6 corpus scenario to the sub-technique it exercises, and correct the technique labels on the scenarios whose rules changed.
- [x] 3.5 Restate the requirement identically in the in-flight delta that also modifies it, since `openspec archive` replaces a requirement whole and the last to archive would otherwise discard the other's text (#815).
- [x] 3.6 Take the technique out of the tamper rule's alert TEXT too, and assert it on the FINDING rather than on the helper that builds the string, since the finding is what persistence carries.
- [x] 3.7 State the behaviour-versus-actor test in the requirement itself, so a reader can tell why one rule keeps a technique it cannot prove intent for and another loses one it can.
- [x] 3.8 Reconcile the two pending requirements that still mandated the tamper technique, since they archive alongside the one forbidding it and would leave the canonical spec contradicting itself.
- [x] 3.9 Sweep every surviving mention of the removed identifiers, not only the ones a reviewer named: the release note, the UAT scenario README, the testing-strategy rule list and a second type-level comment were all still claiming them.
- [x] 3.10 Assert no authored detection declares a parent technique at all, with an empty exception list for the rare ATT&CK technique that has no sub-technique. The two guards above both miss a rule regressing to the parent ALONE with the table edited to match, which is how the two shell-chain rules got there.
- [x] 3.11 Re-run the sweep with `git grep` over EVERY tracked file. The earlier pass filtered by extension, which skipped the shell scripts, and matched on the identifier, which skipped a proposal saying a rule is "mapped to" it in words. Four more claims were still standing.
