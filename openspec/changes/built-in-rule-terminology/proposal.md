# Call the rules that come with the product built-in

## Why

The console labelled a rule that came with the product "shipped". That word describes a release, not where a rule came from, and as a label on a rule it reads as engineering shorthand rather than a fact about the rule. It is also ambiguous: shipped can mean released, included, or delivered to a host.

The term the industry uses for vendor-provided detection content is built-in or prebuilt. Microsoft Sentinel has built-in analytics rules against custom ones; Elastic has prebuilt rules against custom; CrowdStrike and Panther name the vendor. Built-in is the more widely understood of the two, and it is accurate for both sources here, the rules this project writes and the vendored SigmaHQ corpus, since both arrive with the product.

## What changes

The word is replaced wherever it means provenance: the console, the exported ATT&CK Navigator layer, the operator and contributor docs, the server's own identifiers and comments, and this capability's requirements. It is left alone wherever it means a release, which is most of its remaining uses in the tree ("the feature shipped in #875").

Five requirements carry the word in their title, so they are removed and re-added under the renamed title rather than modified in place. No requirement's meaning changes: every scenario is carried across unaltered except for the same substitution in its prose.

## Impact

- Affected specs: `rule-content`
- No behaviour changes. The rename reaches strings an operator reads and identifiers a contributor reads, not what the system does.
- Thirty-five test markers move with the renamed requirements.
