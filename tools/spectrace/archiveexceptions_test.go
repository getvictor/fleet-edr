package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApplyExceptions(t *testing.T) {
	t.Parallel()

	findings := []string{
		"web-ui/alerts-list\n    listed by x, and not in the canonical spec",
		"web-ui/alerts-list/a-scenario\n    listed by x, and not in the canonical spec",
		"web-ui/alerts-list-filters-by-subtype\n    listed by x, and not in the canonical spec",
		"server-rest-api/other\n    listed by x, and not in the canonical spec",
	}

	t.Run("an entry excuses the requirement and its scenarios", func(t *testing.T) {
		t.Parallel()
		out, excused, matched := applyExceptions(findings, []archiveException{{Requirement: "web-ui/alerts-list"}})
		// The sibling whose slug merely starts with the same characters must NOT be swallowed: that is the difference
		// between excusing one reviewed decision and silently muting a neighbouring requirement nobody looked at.
		assert.Equal(t, []string{
			"web-ui/alerts-list-filters-by-subtype\n    listed by x, and not in the canonical spec",
			"server-rest-api/other\n    listed by x, and not in the canonical spec",
		}, out)
		assert.Len(t, excused, 2)
		assert.Equal(t, 2, matched[0])
	})

	t.Run("a capability-only entry excuses nothing", func(t *testing.T) {
		t.Parallel()
		// Review caught this: with prefix matching, `web-ui` alone swallowed every finding in the capability AND passed the
		// not-stale check because it matched plenty, turning an audit record into the blanket mute it exists not to be.
		out, excused, matched := applyExceptions(findings, []archiveException{{Requirement: "web-ui"}})
		assert.Equal(t, findings, out)
		assert.Empty(t, excused)
		assert.Equal(t, 0, matched[0], "a capability-only entry must read as stale, not as excusing the capability")
	})

	t.Run("a scenario-level entry excuses nothing", func(t *testing.T) {
		t.Parallel()
		// The unit is the requirement. Naming a scenario is a mistake that should surface as stale rather than half-work.
		out, _, matched := applyExceptions(findings, []archiveException{{Requirement: "web-ui/alerts-list/a-scenario"}})
		assert.Equal(t, findings, out)
		assert.Equal(t, 0, matched[0])
	})

	t.Run("no entries leaves every finding outstanding", func(t *testing.T) {
		t.Parallel()
		out, excused, _ := applyExceptions(findings, nil)
		assert.Equal(t, findings, out)
		assert.Empty(t, excused)
	})

	t.Run("the first matching entry wins so counts stay attributable", func(t *testing.T) {
		t.Parallel()
		_, _, matched := applyExceptions(findings, []archiveException{
			{Requirement: "web-ui/alerts-list"},
			{Requirement: "web-ui/alerts-list"},
		})
		assert.Equal(t, 2, matched[0])
		assert.Equal(t, 0, matched[1], "a duplicate entry must not double-count, so validation can see it excuses nothing")
	})
}

func TestValidateExceptions(t *testing.T) {
	t.Parallel()
	canonical := map[string]struct{}{"extension-application-control/block-event-emission": {}}

	cases := []struct {
		name    string
		entry   archiveException
		matched int
		want    string
	}{
		{
			name:    "a covered_by that resolves and excuses a finding is accepted",
			entry:   archiveException{Requirement: "a/b", CoveredBy: stringOrList{"extension-application-control/block-event-emission"}, Reason: "why"},
			matched: 1,
			want:    "",
		},
		{
			name:    "a tracked_by entry needs no canonical survivor",
			entry:   archiveException{Requirement: "a/b", TrackedBy: "#929", Reason: "unbuilt"},
			matched: 1,
			want:    "",
		},
		{
			name:    "a covered_by that does not resolve is an error",
			entry:   archiveException{Requirement: "a/b", CoveredBy: stringOrList{"gone/missing"}, Reason: "why"},
			matched: 1,
			want:    "is not a requirement in the canonical spec",
		},
		{
			name:    "an entry excusing nothing is stale",
			entry:   archiveException{Requirement: "a/b", TrackedBy: "#929", Reason: "why"},
			matched: 0,
			want:    "excuses no finding",
		},
		{
			name:    "setting neither disposition is an error",
			entry:   archiveException{Requirement: "a/b", Reason: "why"},
			matched: 1,
			want:    "sets neither covered_by nor tracked_by",
		},
		{
			name:    "setting both dispositions is an error",
			entry:   archiveException{Requirement: "a/b", CoveredBy: stringOrList{"extension-application-control/block-event-emission"}, TrackedBy: "#929", Reason: "w"},
			matched: 1,
			want:    "sets both covered_by and tracked_by",
		},
		{
			name:    "an empty reason is an error",
			entry:   archiveException{Requirement: "a/b", TrackedBy: "#929"},
			matched: 1,
			want:    "reason is empty",
		},
		{
			name:    "an empty requirement is an error",
			entry:   archiveException{TrackedBy: "#929", Reason: "why"},
			matched: 1,
			want:    "requirement is empty",
		},
		{
			name:    "a whitespace-only tracked_by is not a disposition",
			entry:   archiveException{Requirement: "a/b", TrackedBy: "   ", Reason: "why"},
			matched: 1,
			want:    "sets neither covered_by nor tracked_by",
		},
		{
			name:    "a capability-only requirement is rejected by shape",
			entry:   archiveException{Requirement: "web-ui", TrackedBy: "#929", Reason: "why"},
			matched: 1,
			want:    `requirement must be "<capability>/<requirement-slug>"`,
		},
		{
			name:    "a scenario-level requirement is rejected by shape",
			entry:   archiveException{Requirement: "a/b/c", TrackedBy: "#929", Reason: "why"},
			matched: 1,
			want:    `requirement must be "<capability>/<requirement-slug>"`,
		},
		{
			// Canonical keys come from slugify, so neither of these can ever match one; saying so beats "excuses no finding".
			name:    "an unslugged requirement is rejected by shape",
			entry:   archiveException{Requirement: "Web-UI/Alerts List", TrackedBy: "#929", Reason: "why"},
			matched: 1,
			want:    "both slug-formatted",
		},
		{
			name:    "a requirement with a stray space is rejected by shape",
			entry:   archiveException{Requirement: "web-ui/ alerts-list", TrackedBy: "#929", Reason: "why"},
			matched: 1,
			want:    "both slug-formatted",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			problems := validateExceptions([]archiveException{tc.entry}, canonical, map[int]int{0: tc.matched})
			if tc.want == "" {
				assert.Empty(t, problems)
				return
			}
			require.Len(t, problems, 1)
			assert.Contains(t, problems[0], tc.want)
		})
	}

	t.Run("every survivor of a split requirement is verified", func(t *testing.T) {
		t.Parallel()
		// A requirement is sometimes split rather than renamed. Naming only the half that still resolves would let the other
		// half be deleted unnoticed, which is the failure this file exists to prevent.
		entry := archiveException{
			Requirement: "a/b",
			CoveredBy:   stringOrList{"extension-application-control/block-event-emission", "gone/missing"},
			Reason:      "split in two",
		}
		problems := validateExceptions([]archiveException{entry}, canonical, map[int]int{0: 1})
		require.Len(t, problems, 1)
		assert.Contains(t, problems[0], `covered_by "gone/missing" is not a requirement`)
	})

	t.Run("validation and rendering agree on a whitespace-only tracked_by", func(t *testing.T) {
		t.Parallel()
		// The mixed case: a valid covered_by plus a blank tracked_by. Validation must read it as covered, and the report must
		// render the survivor rather than an empty "tracked by".
		e := archiveException{
			Requirement: "a/b",
			CoveredBy:   stringOrList{"extension-application-control/block-event-emission"},
			TrackedBy:   "   ",
			Reason:      "why",
		}
		assert.Empty(t, validateExceptions([]archiveException{e}, canonical, map[int]int{0: 1}))

		var buf bytes.Buffer
		require.Equal(t, 0, printArchiveVerify(&buf, nil,
			[]excusedFinding{{finding: "a/b\n    listed by x", exception: e}}, nil, 5))
		assert.Contains(t, buf.String(), "covered by extension-application-control/block-event-emission")
		assert.NotContains(t, buf.String(), "tracked by  ")
	})

	t.Run("a duplicate requirement is an error", func(t *testing.T) {
		t.Parallel()
		entries := []archiveException{
			{Requirement: "a/b", TrackedBy: "#929", Reason: "why"},
			{Requirement: "a/b", TrackedBy: "#929", Reason: "why"},
		}
		problems := validateExceptions(entries, canonical, map[int]int{0: 1, 1: 0})
		require.Len(t, problems, 1)
		assert.Contains(t, problems[0], "duplicate of entry 1")
	})
}

func TestLoadArchiveExceptions(t *testing.T) {
	t.Parallel()

	t.Run("a missing file is not an error", func(t *testing.T) {
		t.Parallel()
		got, err := loadArchiveExceptions(filepath.Join(t.TempDir(), "absent.yaml"))
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("entries round-trip from yaml", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "e.yaml")
		require.NoError(t, os.WriteFile(path, []byte(
			"- requirement: a/b\n  covered_by: c/d\n  reason: because\n"), 0o600))
		got, err := loadArchiveExceptions(path)
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, archiveException{Requirement: "a/b", CoveredBy: stringOrList{"c/d"}, Reason: "because"}, got[0])
	})

	t.Run("covered_by accepts a list as well as a scalar", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "e.yaml")
		require.NoError(t, os.WriteFile(path, []byte(
			"- requirement: a/b\n  covered_by: [c/d, e/f]\n  reason: split\n"), 0o600))
		got, err := loadArchiveExceptions(path)
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, stringOrList{"c/d", "e/f"}, got[0].CoveredBy)
	})

	t.Run("malformed yaml is an error", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "e.yaml")
		require.NoError(t, os.WriteFile(path, []byte("- requirement: [unclosed\n"), 0o600))
		_, err := loadArchiveExceptions(path)
		require.Error(t, err)
	})
}

func TestPrintArchiveVerifyWithExceptions(t *testing.T) {
	t.Parallel()

	t.Run("excused findings are shown with their survivor, never silently", func(t *testing.T) {
		t.Parallel()
		var buf bytes.Buffer
		excused := []excusedFinding{{
			finding:   "a/b/s\n    listed by x",
			exception: archiveException{Requirement: "a/b", CoveredBy: stringOrList{"c/d"}, Reason: "kept the other copy"},
		}}
		assert.Equal(t, 0, printArchiveVerify(&buf, nil, excused, nil, 5))
		out := buf.String()
		// Each of these is the thing that makes the file an audit record rather than a mute list.
		assert.Contains(t, out, "a/b")
		assert.Contains(t, out, "covered by c/d")
		assert.Contains(t, out, "kept the other copy")
	})

	t.Run("a problem in the exceptions file gates, unlike a finding", func(t *testing.T) {
		t.Parallel()
		var buf bytes.Buffer
		assert.Equal(t, 0, printArchiveVerify(&buf, []string{"a/b\n    listed by x"}, nil, nil, 5),
			"findings alone never gate: the tree carries older ones this pass cannot classify")

		buf.Reset()
		assert.Equal(t, 1, printArchiveVerify(&buf, nil, nil, []string{"a/b: excuses no finding"}, 5),
			"a stale or unresolvable exception silently shrinks the report, so it must fail")
		assert.Contains(t, buf.String(), "excuses no finding")
	})
}

func TestExceptionsPathIsBesideTheSpecsTree(t *testing.T) {
	t.Parallel()
	assert.Equal(t, filepath.Join("openspec", "archive-verify-exceptions.yaml"),
		exceptionsPathFor(filepath.Join("openspec", "specs")))
	// A caller pointed at another checkout gets that checkout's file, not the repository root's.
	assert.Equal(t, filepath.Join("/tmp", "x", "openspec", "archive-verify-exceptions.yaml"),
		exceptionsPathFor(filepath.Join("/tmp", "x", "openspec", "specs")))
}

func TestExceptionReportShowsEveryExcusedLine(t *testing.T) {
	t.Parallel()
	// The defect this pins: printExcused collected the finding heads and then printed only a count, contradicting its own
	// "printed in full" contract. The release checklist diffs two runs of this command, so a scenario newly lost under an
	// EXISTING exception has to move a LINE, not a number, or the diff cannot show what changed.
	var buf bytes.Buffer
	// Two findings that share a head and differ only AFTER the newline, which is the shape textDiff emits for normative text.
	// Printing heads alone made these indistinguishable, so losing one more line of text moved a duplicate line and the release
	// diff still could not say what changed.
	excused := []excusedFinding{
		{finding: "a/b\n    text listed by x, and not in the canonical spec:\n      FIRST normative line",
			exception: archiveException{Requirement: "a/b", TrackedBy: "#1", Reason: "r"}},
		{finding: "a/b\n    text listed by x, and not in the canonical spec:\n      SECOND normative line",
			exception: archiveException{Requirement: "a/b", TrackedBy: "#1", Reason: "r"}},
	}
	require.Equal(t, 0, printArchiveVerify(&buf, nil, excused, nil, 5))
	out := buf.String()
	assert.Contains(t, out, "FIRST normative line")
	assert.Contains(t, out, "SECOND normative line")
}

func TestAllExcusedIsNotReportedAsACleanTree(t *testing.T) {
	t.Parallel()
	// With every finding excused the outstanding list is empty, and the clean-run sentence would otherwise print immediately
	// above a list of real discrepancies. That is the end state this audit is driving toward, so it has to read correctly.
	var buf bytes.Buffer
	excused := []excusedFinding{
		{finding: "a/b/one\n    listed by x", exception: archiveException{Requirement: "a/b", TrackedBy: "#1", Reason: "r"}},
	}
	require.Equal(t, 0, printArchiveVerify(&buf, nil, excused, nil, 5))
	out := buf.String()
	assert.NotContains(t, out, "every scenario still canonical")
	assert.Contains(t, out, "no outstanding findings")

	// A genuinely empty report still says so.
	buf.Reset()
	require.Equal(t, 0, printArchiveVerify(&buf, nil, nil, nil, 5))
	assert.Contains(t, buf.String(), "every scenario still canonical")
}
