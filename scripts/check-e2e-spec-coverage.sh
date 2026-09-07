#!/usr/bin/env bash
# Fail when a Playwright spec under test/e2e/tests/qa/ is named by no phase in scripts/test-e2e-coverage.sh.
#
# That script is the only Playwright run in CI, and it names its qa specs one by one rather than running the directory. The
# explicit list is not an oversight: phases exist to give a group of specs a specific server env, so which phase a spec belongs to
# is a real decision and discovery would erase it. What discovery would also do is guarantee that a spec cannot be forgotten, and
# without it seven were: they sat in the tree named by no phase, never ran, and four had rotted against UI changes made two months
# earlier before anyone noticed (#907).
#
# So the list stays and this closes the hole it leaves. A spec added to the tree must be placed in a phase, in the same PR, or the
# build fails naming it. The check reads the phases out of the script rather than keeping a second list, since a second list is the
# thing that drifts.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

readonly COVERAGE_SCRIPT="scripts/test-e2e-coverage.sh"
readonly SPEC_DIR="test/e2e/tests/qa"

if [[ ! -f "$COVERAGE_SCRIPT" ]]; then
  echo "check-e2e-spec-coverage: $COVERAGE_SCRIPT not found" >&2
  exit 2
fi

# Specs in the tree, as the paths the coverage script writes them ("tests/qa/<name>.spec.ts").
in_tree="$(find "$SPEC_DIR" -name '*.spec.ts' -type f | sed "s|$SPEC_DIR/|tests/qa/|" | sort)"
if [[ -z "$in_tree" ]]; then
  echo "check-e2e-spec-coverage: no specs found under $SPEC_DIR, which cannot be right" >&2
  exit 2
fi

# Specs the script names. Anchored on the same literal path form so a rename in either place shows up as an orphan rather than
# silently matching nothing.
named="$(grep -oE 'tests/qa/[A-Za-z0-9._-]+\.spec\.ts' "$COVERAGE_SCRIPT" | sort -u)"

orphans="$(comm -23 <(echo "$in_tree") <(echo "$named"))"
missing="$(comm -13 <(echo "$in_tree") <(echo "$named"))"

status=0
if [[ -n "$orphans" ]]; then
  status=1
  {
    echo "E2E specs that no phase runs, so CI has never executed them:"
    echo "$orphans" | sed 's/^/  /'
    echo
    echo "Add each to a phase in $COVERAGE_SCRIPT. Pick the phase whose server env the spec needs; the"
    echo "default-env phases are the usual home. A phase starts a fresh server, so its own break-glass"
    echo "setup budget resets, which is the reason to open a new phase rather than grow one indefinitely."
  } >&2
fi

if [[ -n "$missing" ]]; then
  status=1
  {
    echo
    echo "Phases name specs that are not in the tree (renamed or deleted without updating the phase):"
    echo "$missing" | sed 's/^/  /'
  } >&2
fi

if [[ $status -eq 0 ]]; then
  echo "check-e2e-spec-coverage: all $(echo "$in_tree" | wc -l | tr -d ' ') qa specs are named by a phase"
fi
exit $status
