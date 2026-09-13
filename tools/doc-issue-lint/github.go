package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"slices"
	"strconv"
	"strings"
)

const graphQLEndpoint = "https://api.github.com/graphql"

// batchSize caps the aliased issueOrPullRequest fields per GraphQL query, keeping each query well inside GitHub's node limits.
const batchSize = 100

// maxErrorBody bounds how much of a non-200 response body is quoted in the error.
const maxErrorBody = 512

// githubLookup resolves numbers through the GitHub GraphQL API.
type githubLookup struct {
	owner, name string
	endpoint    string
	client      *http.Client
	// token returns the credential. A field so tests can supply one without the environment or the gh CLI.
	token func(ctx context.Context) (string, error)
}

// newGitHubLookup builds the lookup for repo. envToken is the token from the environment (empty when unset); main reads it so
// this file never touches process env.
func newGitHubLookup(repo, envToken string) *githubLookup {
	owner, name, _ := strings.Cut(repo, "/")
	return &githubLookup{
		owner: owner, name: name, endpoint: graphQLEndpoint, client: http.DefaultClient,
		token: func(ctx context.Context) (string, error) { return resolveToken(ctx, envToken) },
	}
}

// resolveToken prefers the token from the environment, then the local gh CLI's stored credential.
func resolveToken(ctx context.Context, envToken string) (string, error) {
	if envToken != "" {
		return envToken, nil
	}
	out, err := exec.CommandContext(ctx, "gh", "auth", "token").Output()
	if err != nil {
		return "", fmt.Errorf("no GITHUB_TOKEN or GH_TOKEN set, and `gh auth token` failed: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

type graphQLResponse struct {
	Data struct {
		Repository map[string]*struct {
			Typename string `json:"__typename"`
			State    string `json:"state"`
			Title    string `json:"title"`
		} `json:"repository"`
	} `json:"data"`
	Errors []struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"errors"`
}

func (g *githubLookup) lookup(ctx context.Context, numbers []int) (map[int]item, error) {
	token, err := g.token(ctx)
	if err != nil {
		return nil, err
	}
	states := make(map[int]item, len(numbers))
	for batch := range slices.Chunk(numbers, batchSize) {
		if err := g.lookupBatch(ctx, token, batch, states); err != nil {
			return nil, err
		}
	}
	return states, nil
}

func buildQuery(owner, name string, numbers []int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "query{repository(owner:%s,name:%s){", strconv.Quote(owner), strconv.Quote(name))
	for _, n := range numbers {
		fmt.Fprintf(&b, "n%d:issueOrPullRequest(number:%d){__typename ...on Issue{state title} ...on PullRequest{state title}} ", n, n)
	}
	b.WriteString("}}")
	return b.String()
}

func (g *githubLookup) lookupBatch(ctx context.Context, token string, numbers []int, states map[int]item) error {
	body, err := json.Marshal(map[string]string{"query": buildQuery(g.owner, g.name, numbers)})
	if err != nil {
		return fmt.Errorf("encode query: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := g.client.Do(req)
	if err != nil {
		return fmt.Errorf("query GitHub: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read GitHub response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GitHub GraphQL returned %s: %s", resp.Status, raw[:min(len(raw), maxErrorBody)])
	}
	var parsed graphQLResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return fmt.Errorf("decode GitHub response: %w", err)
	}
	// A number that does not exist comes back as a NOT_FOUND error beside a null field; that is data (the reference is dangling),
	// not a failed lookup. Any other error means the answer cannot be trusted.
	for _, e := range parsed.Errors {
		if e.Type != "NOT_FOUND" {
			return fmt.Errorf("GitHub GraphQL error: %s", e.Message)
		}
	}
	if parsed.Data.Repository == nil {
		return errors.New("GitHub GraphQL response has no repository (wrong -repo, or the token cannot read it)")
	}
	for _, n := range numbers {
		got := parsed.Data.Repository["n"+strconv.Itoa(n)]
		if got == nil {
			continue
		}
		states[n] = item{kind: itemKind(got.Typename), state: got.State, title: got.Title}
	}
	return nil
}
