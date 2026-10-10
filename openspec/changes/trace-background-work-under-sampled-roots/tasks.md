## 1. Server

- [x] 1.1 The sampling registry classifies a span by name, and the policy registers the detection batch span high-volume
- [x] 1.2 The processor opens a root span per host batch; each periodic sweep pass opens its own root span
- [x] 1.3 One shared otelsql span policy for MySQL and ClickHouse: no span without a parent, no housekeeping spans
- [x] 1.4 Tests: a batch span carries the host and parents the detection call, an unsampled batch drops its children, a sweep pass is one trace, and a query outside a span records no span against a real MySQL
