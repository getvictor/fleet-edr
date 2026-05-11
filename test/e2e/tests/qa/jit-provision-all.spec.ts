// Replaced by the rebuildQAState helper in tests/qa/_setup.ts.
// Each qa/* spec calls rebuildQAState in its own beforeAll so the spec
// is self-bootstrapping. Kept as an empty file to preserve git history;
// remove in the next cleanup pass once the team is on board.
//
// To run the QA matrix from a clean slate:
//   npm run qa                    # all qa/* specs (single worker)
//   npx playwright test tests/qa/role-matrix  # one section at a time
