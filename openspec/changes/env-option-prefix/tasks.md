# Tasks

- [x] Parse env's option prefix before collecting the assignment run, consuming the operand of options that take one and stopping at `--`.
- [x] Clustering follows BSD env: the operand belongs to the last letter, and an attached operand consumes nothing extra.
- [x] An unset of the variable being looked for reads as an unset, not an injection.
- [x] Mutation-tested: no option skipping, options never consuming an operand, the operand belonging to the first letter, and `--` not ending option parsing.
