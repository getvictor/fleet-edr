package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// indexURL is MITRE's published catalogue of ATT&CK releases. It is the only authority on what "latest" means; deriving it from
// a tag list or a docs page would guess.
const indexURL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json"

// enterpriseCollection is the collection whose versions this checks. The bundle also ships Mobile and ICS, which the Coverage
// page does not render.
const enterpriseCollection = "Enterprise ATT&CK"

// checkTimeout bounds the whole network check so a release step cannot hang on a slow or captive network.
const checkTimeout = 30 * time.Second

type indexDocument struct {
	Collections []indexCollection `json:"collections"`
}

type indexCollection struct {
	Name     string         `json:"name"`
	Versions []indexVersion `json:"versions"`
}

type indexVersion struct {
	Version string `json:"version"`
}

// checkLatest reports whether the vendored table is cut from the newest published ATT&CK release.
//
// This is a release-process check rather than a unit test on purpose: it needs the network, and a test that reaches the
// internet fails on an air-gapped runner and turns into noise everyone learns to ignore. The offline half (that the table and
// the Navigator layer agree on a version, and that the table covers every technique a rule maps) is a real test in
// server/rules/bootstrap and runs on every PR.
func checkLatest(tablePath string) error {
	have, err := vendoredVersion(tablePath)
	if err != nil {
		return err
	}
	latest, err := latestPublishedVersion()
	if err != nil {
		return err
	}
	cmp, err := compareVersions(have, latest)
	if err != nil {
		return err
	}
	switch {
	case cmp < 0:
		// The command has to name the NEW version. The task's default is the version already vendored, so telling the operator
		// to run it bare would have them re-cut the release the check just rejected.
		return fmt.Errorf(
			"the vendored ATT&CK table is v%s but MITRE has published v%s; regenerate with "+
				"`task attack:table ATTACK_VERSION=%s` and re-check navigatorATTACKVersion in server/rules/api/navigator.go",
			have, latest, latest)
	case cmp > 0:
		// Ahead of the index usually means a hand-edited version string, which would make the layer claim a release that does
		// not exist. Worth failing rather than passing quietly.
		return fmt.Errorf("the vendored ATT&CK table claims v%s but the newest published release is v%s", have, latest)
	}
	fmt.Printf("attacktable: vendored ATT&CK table is v%s, the newest published release\n", have)
	return nil
}

var vendoredVersionRE = regexp.MustCompile(`ATTACK_VERSION = "([^"]+)"`)

func vendoredVersion(tablePath string) (string, error) {
	raw, err := os.ReadFile(tablePath) //nolint:gosec // repo-relative path to a generated file
	if err != nil {
		return "", fmt.Errorf("read %s: %w", tablePath, err)
	}
	m := vendoredVersionRE.FindSubmatch(raw)
	if m == nil {
		return "", fmt.Errorf("%s declares no ATTACK_VERSION", tablePath)
	}
	return string(m[1]), nil
}

func latestPublishedVersion() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), checkTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, indexURL, nil)
	if err != nil {
		return "", fmt.Errorf("build index request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch %s: %w", indexURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetch %s: HTTP %d", indexURL, resp.StatusCode)
	}
	var doc indexDocument
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return "", fmt.Errorf("decode index: %w", err)
	}
	latest := ""
	for _, c := range doc.Collections {
		if c.Name != enterpriseCollection {
			continue
		}
		for _, v := range c.Versions {
			// The index is not ordered newest-last, so this compares rather than taking the tail.
			if latest == "" {
				latest = v.Version
				continue
			}
			cmp, err := compareVersions(v.Version, latest)
			if err != nil {
				return "", err
			}
			if cmp > 0 {
				latest = v.Version
			}
		}
	}
	if latest == "" {
		return "", fmt.Errorf("index lists no versions for %q", enterpriseCollection)
	}
	return latest, nil
}

// compareVersions orders two dotted numeric ATT&CK versions. String comparison will not do: "9.0" sorts after "19.2".
func compareVersions(a, b string) (int, error) {
	pa, err := parseVersion(a)
	if err != nil {
		return 0, err
	}
	pb, err := parseVersion(b)
	if err != nil {
		return 0, err
	}
	for i := 0; i < len(pa) || i < len(pb); i++ {
		x, y := 0, 0
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x != y {
			if x < y {
				return -1, nil
			}
			return 1, nil
		}
	}
	return 0, nil
}

func parseVersion(v string) ([]int, error) {
	parts := strings.Split(v, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("version %q is not dotted-numeric: %w", v, err)
		}
		out = append(out, n)
	}
	return out, nil
}
