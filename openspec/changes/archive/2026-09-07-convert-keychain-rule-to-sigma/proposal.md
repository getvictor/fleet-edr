# A converted rule carries its logic in its file

## Why

#761 converts the Sigma-expressible detections from Go to `detection:` blocks. #790 established that the three reachable rules need computed fields to be expressible at all, and proved each field reproduces the Go matcher it replaces. This is the first conversion: the machinery a converted rule needs, and `credential_keychain_dump` moved onto it.

## What changes

A rule file can now carry a Sigma `detection:` block, and that block is the rule's logic. The pack loader compiles every block when the catalog is built, checks each field against the taxonomy for the rule's logsource category, and refuses anything malformed, for the same reason parameters are validated at load: a detection that fails at first fire, on one host, is indistinguishable from the behaviour never occurring.

`credential_keychain_dump` is converted. Its match values move from `x-engine.params` into the detection block, which is where Sigma puts them, and it no longer names a Go evaluator, because the block is what decides it now.

## Type and portability are derived, not declared

Both were hardcoded (`graph`, `none`) while every rule was Go. They are now computed from the rule: a detection block makes it `sigma`, and it is `standard` when every field it reads comes from Sigma's own taxonomy or `mapped` when any is one we compute. This is what epic #756 specified ("portability is computed, not declared"), and it matters because `portable` is the field that tells another team whether they can run our rule.

The converted rule is `mapped`: it reads `Subcommand`, which exists because Sigma represents a command line as a single string in which argument position is not recoverable.

## The gate

The rule's five fixtures are **byte-for-byte unchanged**, and its test file gains only a spec marker comment: no assertion, no fixture and no expectation was touched to make the conversion pass. That is #761's acceptance criterion stated literally. Beyond that, the Go matcher is retained in the equivalence test as a frozen oracle, so the property that proved the conversion keeps proving it: replacing the shipped detection with the `CommandLine|contains` form the issue originally proposed fails the gate, which is exactly the regression it exists to prevent.

## Impact

No behaviour change. The rule detects what it detected, and the evidence is the tests that were already pinning it.
