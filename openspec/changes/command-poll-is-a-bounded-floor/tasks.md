# Tasks

- [x] Bound the stream deferral by a floor interval instead of by the agent's belief
- [x] Start the floor clock at construction so the contract has no special startup case
- [x] Tests for the wedge, the steady state, and a known-down stream, mutation-checked
- [x] Share an in-flight tracker between the transports so the floor cannot make one report a running command failed
- [x] Spec delta recording that a passing liveness probe is not proof of delivery, and the at-most-once rule across transports
