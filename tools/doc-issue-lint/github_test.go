package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

// aliasPattern pulls the requested numbers back out of a query, so the fake server answers exactly what it was asked.
var aliasPattern = regexp.MustCompile(`n(\d+):issueOrPullRequest`)

// fakeGraphQL serves canned answers per number. A number missing from answers gets GitHub's NOT_FOUND shape.
func fakeGraphQL(t *testing.T, answers map[int]string, calls *atomic.Int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "bearer test-token" {
			http.Error(w, "bad credentials", http.StatusUnauthorized)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Query string `json:"query"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		fields := []string{}
		errs := []string{}
		for _, m := range aliasPattern.FindAllStringSubmatch(req.Query, -1) {
			n, _ := strconv.Atoi(m[1])
			if a, ok := answers[n]; ok {
				fields = append(fields, `"n`+m[1]+`":`+a)
				continue
			}
			fields = append(fields, `"n`+m[1]+`":null`)
			errs = append(errs, `{"type":"NOT_FOUND","message":"Could not resolve to an issue or pull request with the number of `+m[1]+`."}`)
		}
		resp := `{"data":{"repository":{` + strings.Join(fields, ",") + `}}`
		if len(errs) > 0 {
			resp += `,"errors":[` + strings.Join(errs, ",") + `]`
		}
		_, _ = w.Write([]byte(resp + "}"))
	}))
}

func testLookup(endpoint string) *githubLookup {
	g := newGitHubLookup(defaultRepo, "")
	g.endpoint = endpoint
	g.token = func(context.Context) (string, error) { return "test-token", nil }
	return g
}

func TestGitHubLookup(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	srv := fakeGraphQL(t, map[int]string{
		565:  `{"__typename":"Issue","state":"OPEN","title":"webhook hardening"}`,
		776:  `{"__typename":"Issue","state":"CLOSED","title":"split suspicious_exec"}`,
		1023: `{"__typename":"PullRequest","state":"MERGED","title":"docs"}`,
	}, &calls)
	defer srv.Close()

	got, err := testLookup(srv.URL).lookup(t.Context(), []int{565, 776, 1023, 99999})
	if err != nil {
		t.Fatal(err)
	}
	want := map[int]item{
		565:  {kind: kindIssue, state: "OPEN", title: "webhook hardening"},
		776:  {kind: kindIssue, state: "CLOSED", title: "split suspicious_exec"},
		1023: {kind: kindPullRequest, state: "MERGED", title: "docs"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v (99999 must be absent, not an error)", got, want)
	}
	for n, w := range want {
		if got[n] != w {
			t.Errorf("number %d: got %+v, want %+v", n, got[n], w)
		}
	}
}

func TestGitHubLookupBatches(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	srv := fakeGraphQL(t, map[int]string{}, &calls)
	defer srv.Close()
	numbers := make([]int, batchSize+1)
	for i := range numbers {
		numbers[i] = i + 1
	}
	if _, err := testLookup(srv.URL).lookup(t.Context(), numbers); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("made %d requests for %d numbers, want 2", calls.Load(), len(numbers))
	}
}

func TestGitHubLookupFailures(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		status  int
		body    string
		wantErr string
	}{
		{"non-200 status", http.StatusUnauthorized, `{"message":"Bad credentials"}`, "401"},
		{"non NOT_FOUND GraphQL error", http.StatusOK, `{"data":null,"errors":[{"type":"RATE_LIMITED","message":"slow down"}]}`, "slow down"},
		{"repository missing", http.StatusOK, `{"data":{"repository":null}}`, "no repository"},
		{"malformed body", http.StatusOK, `not json`, "decode"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			_, err := testLookup(srv.URL).lookup(t.Context(), []int{1})
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want one containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestBuildQueryQuotesRepo(t *testing.T) {
	t.Parallel()
	q := buildQuery("getvictor", "fleet-edr", []int{7, 12})
	for _, want := range []string{`repository(owner:"getvictor",name:"fleet-edr")`, "n7:issueOrPullRequest(number:7)", "n12:issueOrPullRequest(number:12)"} {
		if !strings.Contains(q, want) {
			t.Errorf("query %q missing %q", q, want)
		}
	}
}

func TestGitHubLookupWithoutToken(t *testing.T) {
	t.Parallel()
	g := testLookup("http://127.0.0.1:1")
	g.token = func(context.Context) (string, error) { return "", errors.New("no credential") }
	if _, err := g.lookup(t.Context(), []int{1}); err == nil || !strings.Contains(err.Error(), "no credential") {
		t.Fatalf("err = %v, want the credential error", err)
	}
}

func TestResolveToken(t *testing.T) {
	t.Parallel()
	got, err := resolveToken(t.Context(), "from-env")
	if err != nil || got != "from-env" {
		t.Fatalf("resolveToken = %q, %v; want the environment token", got, err)
	}
	if _, err := resolveToken(t.Context(), ""); err == nil {
		t.Fatal("resolveToken with no token succeeded; want an error naming GITHUB_TOKEN")
	}
}
