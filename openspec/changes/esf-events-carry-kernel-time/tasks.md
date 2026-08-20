# Tasks

- [x] `serialize` accepts the kernel event time, falling back to the produced-at clock for callers with no kernel message
- [x] Thread `es_message_t.time` through exec, fork, exit, open, BTM, and the two application-control audit events
- [x] Unit tests for the conversion and for the fallback
- [x] Verify on a live VM that the recorded exec time matches ground truth rather than trailing it
- [x] Spec delta for the envelope's timestamp semantics
