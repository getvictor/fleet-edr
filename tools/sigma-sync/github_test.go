package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func fakeGitHub(t *testing.T, truncated bool) (*github, *[]string) {
	t.Helper()
	var auth []string
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/repos/SigmaHQ/sigma/commits/master", func(w http.ResponseWriter, r *http.Request) {
		auth = append(auth, "api:"+r.Header.Get("Authorization"))
		assert.Equal(t, "application/vnd.github.sha", r.Header.Get("Accept"))
		_, _ = w.Write([]byte("abc123\n"))
	})
	mux.HandleFunc("GET /api/repos/SigmaHQ/sigma/git/trees/abc123", func(w http.ResponseWriter, r *http.Request) {
		auth = append(auth, "api:"+r.Header.Get("Authorization"))
		assert.Equal(t, "1", r.URL.Query().Get("recursive"))
		_, _ = w.Write([]byte(`{"truncated":` + map[bool]string{true: "true", false: "false"}[truncated] + `,"tree":[` +
			`{"path":"rules/macos","type":"tree","sha":"t1"},` +
			`{"path":"rules/macos/process_creation/a.yml","type":"blob","sha":"b1"}]}`))
	})
	mux.HandleFunc("GET /raw/SigmaHQ/sigma/abc123/rules/macos/process_creation/a.yml", func(w http.ResponseWriter, r *http.Request) {
		auth = append(auth, "raw:"+r.Header.Get("Authorization"))
		_, _ = w.Write([]byte("title: a\n"))
	})
	mux.HandleFunc("GET /raw/SigmaHQ/sigma/abc123/missing.yml", func(w http.ResponseWriter, _ *http.Request) {
		http.NotFound(w, nil)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	g := newGitHub("SigmaHQ/sigma", "master", "secret")
	g.apiBase, g.rawBase, g.client = srv.URL+"/api", srv.URL+"/raw", srv.Client()
	return g, &auth
}

func TestGitHub_SnapshotAndFileReadOneCommit(t *testing.T) {
	t.Parallel()
	g, auth := fakeGitHub(t, false)

	commit, entries, err := g.Snapshot(t.Context())
	require.NoError(t, err)
	assert.Equal(t, "abc123", commit)
	assert.Equal(t, []treeEntry{{Path: "rules/macos/process_creation/a.yml", BlobSHA: "b1"}}, entries, "directories are not files")

	content, err := g.File(t.Context(), commit, "rules/macos/process_creation/a.yml")
	require.NoError(t, err)
	assert.Equal(t, "title: a\n", string(content))
	assert.Equal(t, []string{"api:Bearer secret", "api:Bearer secret", "raw:"}, *auth, "the token goes to the API and never to the raw host")

	_, err = g.File(t.Context(), commit, "missing.yml")
	require.ErrorContains(t, err, "404")
}

func TestGitHub_RefusesATruncatedTree(t *testing.T) {
	t.Parallel()
	g, _ := fakeGitHub(t, true)
	_, _, err := g.Snapshot(t.Context())
	require.ErrorContains(t, err, "too large for one listing")
}
