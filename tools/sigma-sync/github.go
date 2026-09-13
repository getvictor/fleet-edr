package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// maxFileBytes bounds one downloaded rule file. SigmaHQ's macOS rules are a few kilobytes; the bound only stops a misbehaving
// response from being read without limit.
const maxFileBytes = 1 << 20

// maxTreeBytes bounds the recursive tree listing, which for SigmaHQ is several megabytes of JSON.
const maxTreeBytes = 64 << 20

// github reads a snapshot of a GitHub repository: the commit a ref points at, its recursive tree, and files at that commit.
type github struct {
	repo    string
	ref     string
	apiBase string
	rawBase string
	token   string
	client  *http.Client
}

func newGitHub(repo, ref, token string) *github {
	return &github{
		repo: repo, ref: ref, token: token, client: http.DefaultClient,
		apiBase: "https://api.github.com", rawBase: "https://raw.githubusercontent.com",
	}
}

// Snapshot resolves the ref to a commit and lists every file in that commit, so every read that follows sees one consistent tree.
func (g *github) Snapshot(ctx context.Context) (string, []treeEntry, error) {
	commitBody, err := g.get(ctx, g.apiBase+"/repos/"+g.repo+"/commits/"+url.PathEscape(g.ref), "application/vnd.github.sha", true, 1024)
	if err != nil {
		return "", nil, fmt.Errorf("resolve %s: %w", g.ref, err)
	}
	commit := strings.TrimSpace(string(commitBody))

	treeBody, err := g.get(ctx, g.apiBase+"/repos/"+g.repo+"/git/trees/"+commit+"?recursive=1", "application/vnd.github+json", true,
		maxTreeBytes)
	if err != nil {
		return "", nil, fmt.Errorf("list tree at %s: %w", commit, err)
	}
	var tree struct {
		Tree []struct {
			Path string `json:"path"`
			Type string `json:"type"`
			SHA  string `json:"sha"`
		} `json:"tree"`
		Truncated bool `json:"truncated"`
	}
	if err := json.Unmarshal(treeBody, &tree); err != nil {
		return "", nil, fmt.Errorf("decode tree at %s: %w", commit, err)
	}
	// A truncated listing would read as rules withdrawn upstream, so it is an error rather than a partial answer.
	if tree.Truncated {
		return "", nil, fmt.Errorf("the tree at %s is too large for one listing", commit)
	}
	entries := make([]treeEntry, 0, len(tree.Tree))
	for _, e := range tree.Tree {
		if e.Type == "blob" {
			entries = append(entries, treeEntry{Path: e.Path, BlobSHA: e.SHA})
		}
	}
	return commit, entries, nil
}

// File returns a file's bytes at a commit.
func (g *github) File(ctx context.Context, commit, repoPath string) ([]byte, error) {
	segments := strings.Split(repoPath, "/")
	for i, s := range segments {
		segments[i] = url.PathEscape(s)
	}
	return g.get(ctx, g.rawBase+"/"+g.repo+"/"+commit+"/"+strings.Join(segments, "/"), "", false, maxFileBytes)
}

// get fetches one URL. The token goes only to the API, never to the raw content host, which serves public files without one.
func (g *github) get(ctx context.Context, target, accept string, api bool, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	if api && g.token != "" {
		req.Header.Set("Authorization", "Bearer "+g.token)
	}
	resp, err := g.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", target, resp.Status)
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("GET %s: response exceeds %d bytes", target, limit)
	}
	return body, nil
}
