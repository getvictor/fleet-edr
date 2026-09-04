# Tasks

- [x] Parse env's option prefix before collecting the assignment run, consuming the operand of options that take one and stopping at `--`.
- [x] Clustering follows BSD env, measured against `env(1)` rather than assumed: an operand-taking letter takes the REST of its own token when there is one, and the next argument only when there is not. `env -uS A=1 prog` therefore unsets S and applies A=1.
- [x] Validate the option letters against env's actual set (`-0iv`, `-C`, `-P`, `-S`, `-u`) and report nothing for an invocation env would refuse, since it execs nothing.
- [x] End the assignment run on whether a token assigns at all, not on whether a shell would accept the name, and narrow only the REPORTED set to well-formed assignments.
- [x] An unset of the variable being looked for reads as an unset, not an injection.
- [x] Mutation-tested: no option skipping, options never consuming an operand, the operand belonging to the first letter, `--` not ending option parsing, the refusal neutered, and the boundary tightened to the report filter. Two mutants initially "survived" because they preserved behaviour; the third attempt found that the refusal is only observable when the offending token itself carries an equals sign, and a test for that shape was added.
