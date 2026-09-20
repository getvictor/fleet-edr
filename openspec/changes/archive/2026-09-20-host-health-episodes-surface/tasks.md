# Tasks

- [x] The host detail read reports recorded sensor faults, open first, each half bounded, including for a host with no snapshot
- [x] The overall health status is not raised by a recorded fault
- [x] The Details popover lists recorded faults with the part at fault, the reason in words, and how long a resolved one lasted
- [x] Outage duration rounds rather than floors, because subtracting two epoch-nanosecond instants loses precision
- [x] The integration stack wires the fault recorder the way the server's startup does
- [x] The efficacy harness reads `expect`, and a health-episode scenario fails if an alert was raised as well
- [x] Mutation-check the no-snapshot path, the ordering, and the stack wiring
- [x] Manual QA on the dev server and in the console
