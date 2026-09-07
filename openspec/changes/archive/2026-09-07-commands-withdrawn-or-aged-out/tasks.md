# Tasks

- [x] Add `cancelled` and `expired` terminal states, reachable only from pending, with the ENUM migration
- [x] Add the operator cancel route, gated on the authority to issue that command type
- [x] Age out commands past the delivery window on the delivery read, scoped per host
- [x] Integration tests for withdrawal, refusal once acked, ageing out, and leaving an acked command alone
- [x] Spec delta
