// Replaced by the rebuildQAState helper in tests/qa/_setup.ts.
// Each qa/* spec calls rebuildQAState in its own beforeAll so the spec
// is self-bootstrapping. Kept as an empty file to preserve git history;
// remove in the next cleanup pass once the team is on board.
//
// To run the QA matrix from a clean slate:
//   npm run qa                                      # all qa/* specs (single worker)
//   npx playwright test tests/qa/sections-c-d-f     # one consolidated section file
//
// The other files in tests/qa/ (role-matrix, reauth-window,
// audit-and-recovery) are also stubs — sections C, D, and F.4 are
// consolidated into sections-c-d-f.spec.ts so the global break-glass
// setup rate-limit (5/min) only fires once per `npm run qa` run.
