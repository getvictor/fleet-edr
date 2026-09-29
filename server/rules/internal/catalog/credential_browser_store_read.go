package catalog

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/fleetdm/edr/server/rules/api"
)

// CredentialBrowserStoreRead fires when a program other than the browser opens a browser's saved passwords, cookies, or the key
// material that decrypts them (T1555.003). Reading these files is what an infostealer does, and it is the part of one the host can
// see: the files are opened, copied or queried, and then sent elsewhere.
//
// The events are `open` events from the security extension's credential-store client (issue #1187), which watches exactly these
// files and already drops opens by the browser's own team. The rule applies that owner check again to the process graph's
// signature, then skips Apple's backup and indexing services, which read every file on the disk.
type CredentialBrowserStoreRead struct {
	// Exclusions is the per-host false-positive resolver, consulted for the opener's path, team, team-qualified signing identifier
	// and cdhash. Nil excludes nothing.
	Exclusions api.ExclusionResolver
}

// credentialStore is one browser's credential files as the rule recognizes them: the directory they live in below a home, the team
// that signs the browser, and the names of the files.
type credentialStore struct {
	name  string
	root  string
	team  string
	files []string
}

// chromiumCredentialFiles are a Chromium browser's saved passwords, form data, cookies and the key material beside its profiles.
var chromiumCredentialFiles = []string{"Login Data", "Login Data For Account", "Web Data", "Cookies", "Local State"}

// credentialStores mirrors the extension's CredentialStores.browsers. The extension decides what is watched; this list names the
// browser in the alert and applies the owner check to the signature the graph holds.
var credentialStores = []credentialStore{
	{"Chrome", "/Library/Application Support/Google/Chrome/", "EQHXZ8M8AV", chromiumCredentialFiles},
	{"Brave", "/Library/Application Support/BraveSoftware/Brave-Browser/", "KL8N8XSYF4", chromiumCredentialFiles},
	{"Edge", "/Library/Application Support/Microsoft Edge/", "UBF8T346G9", chromiumCredentialFiles},
	{"Arc", "/Library/Application Support/Arc/User Data/", "S6N382Y83G", chromiumCredentialFiles},
	{"Vivaldi", "/Library/Application Support/Vivaldi/", "4XF3XNRN6Y", chromiumCredentialFiles},
	{"Firefox", "/Library/Application Support/Firefox/Profiles/", "43AQ936H96", []string{"logins.json", "key4.db", "cookies.sqlite"}},
}

// indexingAndBackup are Apple's services that read every file on the disk: Time Machine and Spotlight. Their reads of a credential
// store are routine, and judged by the platform-qualified signing identifier, which a program that is not Apple's cannot claim.
var indexingAndBackup = []string{
	"platform:com.apple.backupd",
	"platform:com.apple.mds",
	"platform:com.apple.mds_stores",
	"platform:com.apple.mdworker_shared",
}

func (r *CredentialBrowserStoreRead) ID() string { return "credential_browser_store_read" }

// AlgorithmName names the evaluator that decides this rule, for the exported rule file.
func (r *CredentialBrowserStoreRead) AlgorithmName() string { return "credential_store_opener_verdict" }

// SupportedExclusionMatchTypes lists what an operator can waive an opener by: its path, its team, its team-qualified signing
// identifier, or its cdhash, as for the exec chain rules.
func (r *CredentialBrowserStoreRead) SupportedExclusionMatchTypes() []api.ExclusionMatchType {
	return []api.ExclusionMatchType{
		api.ExclusionMatchPathGlob, api.ExclusionMatchTeamID, api.ExclusionMatchSigningID, api.ExclusionMatchCDHash,
	}
}

// DisplayName is the canonical human-readable name reused by Doc().Title and the finding (issue #519).
func (r *CredentialBrowserStoreRead) DisplayName() string { return "Browser credential store read" }

// Techniques returns T1555.003 (Credentials from Password Stores: Credentials from Web Browsers).
func (r *CredentialBrowserStoreRead) Techniques() []string { return []string{"T1555.003"} }

// Doc surfaces the operator-facing description in /api/rules and the generated docs/detection-rules.md.
func (r *CredentialBrowserStoreRead) Doc() api.Documentation {
	return api.Documentation{
		Title:   r.DisplayName(),
		Summary: "Flags a program other than the browser opening a browser's saved passwords, cookies or their key material.",
		Description: "Detects credential theft from web browsers on macOS (T1555.003), the core behavior of infostealers: a " +
			"program opening Chrome's, Brave's, Edge's, Arc's, Vivaldi's or Firefox's saved logins, cookies, form data or the key " +
			"material that decrypts them.\n\n" +
			"The browser's own reads are not reported, judged by the team that signs it, and neither are Time Machine's and " +
			"Spotlight's. Apple's command-line tools are reported, since `cp`, `sqlite3` and `ditto` are what these files are " +
			"read with. One alert is raised per process, however many files it opens.",
		Severity:   api.SeverityHigh,
		EventTypes: []string{"open"},
		FalsePositives: []string{
			"A backup, sync or security tool that reads the whole home folder (Backblaze, Arq, an antivirus scanner). Exclude it " +
				"by `team_id`, which survives upgrades and cannot be claimed by another program.",
			"A person or script exporting their own browser data by hand. Confirm with them; the opener is their shell or tool.",
			"A password manager importing from a browser. Exclude it by `team_id`.",
		},
		Limitations: []string{
			"Safari's cookies are not watched.",
			"A browser at a custom profile location, or a Chromium browser not listed here, is not watched.",
			"Needs an agent whose extension reports reads of these files.",
		},
	}
}

func (r *CredentialBrowserStoreRead) Evaluate(ctx context.Context, events []api.Event, s api.GraphReader) ([]api.Finding, error) {
	return r.EvaluateScoped(ctx, &api.BatchScope{}, events, s)
}

// CountsMaterializationAbandons declares that every abandon this rule makes is recorded, so its zero is a measurement.
func (r *CredentialBrowserStoreRead) CountsMaterializationAbandons() {}

// EvaluateScoped implements api.ScopedRule.
func (r *CredentialBrowserStoreRead) EvaluateScoped(
	ctx context.Context, scope *api.BatchScope, events []api.Event, s api.GraphReader,
) ([]api.Finding, error) {
	return evalEachScopedEvent(ctx, scope, events, s, r.evalEvent)
}

func (r *CredentialBrowserStoreRead) evalEvent(
	ctx context.Context, scope *api.BatchScope, evt api.Event, s api.GraphReader,
) (*api.Finding, error) {
	if evt.EventType != "open" {
		return nil, nil
	}
	var p struct {
		PID  int    `json:"pid"`
		Path string `json:"path"`
	}
	if err := json.Unmarshal(evt.Payload, &p); err != nil || p.PID <= 0 {
		return nil, nil
	}
	store, file, ok := credentialFile(p.Path)
	if !ok {
		return nil, nil
	}
	proc, err := resolveSubjectProcess(ctx, s, evt, p.PID)
	if err != nil {
		return nil, err
	}
	if proc == nil {
		scope.RecordMaterializationAbandoned(r.ID(), p.PID)
		return nil, nil
	}
	cs := processSignature(proc)
	if cs.TeamID == store.team || slices.Contains(indexingAndBackup, api.QualifiedSigningID(cs.TeamID, cs.SigningID, cs.IsPlatformBinary)) {
		return nil, nil
	}
	if r.Exclusions != nil && processExcluded(r.Exclusions, r.ID(), api.ExclusionMatchPathGlob, proc, evt.HostID) {
		return nil, nil
	}
	return &api.Finding{
		HostID:      evt.HostID,
		RuleID:      r.ID(),
		Severity:    api.SeverityHigh,
		Title:       r.DisplayName(),
		Description: fmt.Sprintf("%s opened %s's %s: browser credential theft (MITRE T1555.003)", proc.Path, store.name, file),
		ProcessID:   proc.ID,
		EventIDs:    []string{evt.EventID},
	}, nil
}

// credentialFile names the browser and the credential file a path is, or ok is false for any other path. The path must lie in the
// browser's directory below a home and end in one of its credential file names.
func credentialFile(path string) (credentialStore, string, bool) {
	for _, store := range credentialStores {
		if !strings.Contains(path, store.root) {
			continue
		}
		for _, name := range store.files {
			if strings.HasSuffix(path, "/"+name) {
				return store, name, true
			}
		}
	}
	return credentialStore{}, "", false
}

// processSignature is a process's persisted code signature, or the zero value when it has none or it does not decode.
func processSignature(proc *api.Process) codeSigningJSON {
	var cs codeSigningJSON
	if len(proc.CodeSigning) > 0 {
		_ = json.Unmarshal(proc.CodeSigning, &cs)
	}
	return cs
}
