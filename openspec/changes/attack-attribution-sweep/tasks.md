# Tasks

## 1. Correct the mappings that were not earned

- [x] 1.1 Drop Spearphishing Attachment from the Office rule, keeping the phishing context in the description.
- [x] 1.2 Drop Ingress Tool Transfer from both shell-chain rules, neither of which observes anything arriving.
- [x] 1.3 Move both from the parent interpreter technique to the Unix Shell sub-technique, which each matches by path.
- [x] 1.4 Resolve the drift where a type comment named User Execution while the code declared Ingress Tool Transfer: drop both rather than pick a survivor, since neither is observed.

## 2. Decide the arguable ones explicitly

- [x] 2.1 Keep the sensor-tamper mapping, recording that the timing separation is the observation and what would change the answer.
- [x] 2.2 Keep the AppleScript dropper's mapping, recording that the download is required to reach a finding at all, which is what the issue assumed was optional.

## 3. Make the mapping hard to change by accident

- [x] 3.1 Pin the whole first-party mapping as one exact set, with the observation that earns each entry.
- [x] 3.2 Assert no rule declares both a parent technique and its own sub-technique, which the exact set alone cannot express.
- [x] 3.3 Regenerate the rule reference, the Navigator layer and the rule pack, and read the coverage diff as the deliberate change it is.
- [x] 3.4 Rename the L6 corpus scenario to the sub-technique it exercises, and correct the technique labels on the scenarios whose rules changed.
- [x] 3.5 Restate the requirement identically in the in-flight delta that also modifies it, since `openspec archive` replaces a requirement whole and the last to archive would otherwise discard the other's text (#815).
- [x] 3.7 Take the technique out of the tamper rule's alert TEXT too, and assert it on the FINDING rather than on the helper that builds the string, since the finding is what persistence carries.
- [x] 3.8 State the behaviour-versus-actor test in the requirement itself, so a reader can tell why one rule keeps a technique it cannot prove intent for and another loses one it can.
