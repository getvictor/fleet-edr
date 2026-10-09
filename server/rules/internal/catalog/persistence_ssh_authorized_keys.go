package catalog

import (
	"bytes"
	"context"
	"fmt"
	"sync"

	"github.com/fleetdm/edr/server/rules/api"
	"github.com/fleetdm/edr/server/rules/internal/sigma"
)

// PersistenceSSHAuthorizedKeys fires when a file sshd reads a user's authorized public keys from is written, or renamed into
// place: `~/.ssh/authorized_keys` or `~/.ssh/authorized_keys2` in any home, root's included. A key added there lets whoever holds
// the private half log in as that user from then on, which is persistence that survives a password change (T1098.004).
//
// The files are watched in every home through the `~/` defaults (issue #1167), which each host's extension expands into root's
// and each person's home. A host whose extension predates that expansion reports nothing here.
//
// Like sudoers_tamper, it does not filter on platform binaries: keys are added by `cat >>`, `tee` and `ssh-copy-id`'s remote
// shell, all Apple's own, so a platform filter would silence every realistic case. Operators tune with a path-glob exclusion on
// the writer.
type PersistenceSSHAuthorizedKeys struct {
	// Exclusions is the per-host false-positive resolver, consulted for the writer's path. Nil excludes nothing.
	Exclusions api.ExclusionResolver
}

func (r *PersistenceSSHAuthorizedKeys) ID() string { return "persistence_ssh_authorized_keys" }

// DisplayName is the canonical human-readable name reused by Doc().Title and the finding (issue #519).
func (r *PersistenceSSHAuthorizedKeys) DisplayName() string { return "SSH authorized keys changed" }

// Techniques returns T1098.004 (Account Manipulation: SSH Authorized Keys).
func (r *PersistenceSSHAuthorizedKeys) Techniques() []string { return []string{"T1098.004"} }

// SupportedExclusionMatchTypes is the writer's path, as for the sudoers rules.
func (r *PersistenceSSHAuthorizedKeys) SupportedExclusionMatchTypes() []api.ExclusionMatchType {
	return []api.ExclusionMatchType{api.ExclusionMatchPathGlob}
}

// Doc surfaces the operator-facing description in /api/rules and the generated docs/detection-rules.md.
func (r *PersistenceSSHAuthorizedKeys) Doc() api.Documentation {
	return api.Documentation{
		Title:   r.DisplayName(),
		Summary: "Flags a write to, or a rename onto, a user's SSH authorized_keys file.",
		Description: "Detects SSH key persistence on macOS (T1098.004): a public key added to `~/.ssh/authorized_keys` (or " +
			"`authorized_keys2`) lets whoever holds the private key log in as that user, and keeps working after the user's " +
			"password changes. Every home is watched, root's included.\n\n" +
			"The rule reads renames as well as writes, so a key file prepared elsewhere and moved into place is caught. It does " +
			"not filter on Apple-signed tools, because keys are added with `cat`, `tee` and `ssh-copy-id`'s remote shell.",
		Severity:   api.SeverityMedium,
		EventTypes: []string{"open", "file_rename"},
		FalsePositives: []string{
			"A person adding their own key, by hand or with `ssh-copy-id` from another machine. Confirm with them; the writer " +
				"is their shell or editor.",
			"Configuration management that distributes keys (Ansible, Chef, Puppet, an MDM script). Add a path-glob exclusion " +
				"for the agent's absolute path.",
		},
		Limitations: []string{
			"A key file sshd_config names with a custom `AuthorizedKeysFile` is not detected: the rule matches only the default " +
				"`authorized_keys` and `authorized_keys2` names, and watching another name only records its writes.",
			"Removing a key, or deleting the file, is not reported: removal takes access away rather than granting it.",
		},
	}
}

// authorizedKeysBytes is the fast-path filter applied to the raw payload before decoding: every write to a watched path reaches
// this rule, and only these names can match. It holds no slash, so it matches whether or not the path's slashes arrive escaped.
var authorizedKeysBytes = []byte("authorized_keys")

// authorizedKeysDetection is the rule's logic, compiled from the detection block in its pack file.
var authorizedKeysDetection = sync.OnceValue(func() *sigma.Rule { return detectionFor("persistence_ssh_authorized_keys") })

func (r *PersistenceSSHAuthorizedKeys) Evaluate(ctx context.Context, events []api.Event, s api.GraphReader) ([]api.Finding, error) {
	return r.EvaluateScoped(ctx, &api.BatchScope{}, events, s)
}

// CountsMaterializationAbandons declares that every abandon this rule makes is recorded, through the shared Sigma view, so its
// zero is a measurement.
func (r *PersistenceSSHAuthorizedKeys) CountsMaterializationAbandons() {}

// EvaluateScoped implements api.ScopedRule.
func (r *PersistenceSSHAuthorizedKeys) EvaluateScoped(
	ctx context.Context, scope *api.BatchScope, events []api.Event, s api.GraphReader,
) ([]api.Finding, error) {
	return evalEachScopedEvent(ctx, scope, events, s, r.evalEvent)
}

func (r *PersistenceSSHAuthorizedKeys) evalEvent(
	ctx context.Context, scope *api.BatchScope, evt api.Event, s api.GraphReader,
) (*api.Finding, error) {
	// A rename's TargetFilename is its destination, so one detection asks both events whether a key file was just changed.
	if evt.EventType != "open" && evt.EventType != "file_rename" {
		return nil, nil
	}
	if !bytes.Contains(evt.Payload, authorizedKeysBytes) {
		return nil, nil
	}
	view := sigmaEvent(ctx, scope, evt, s)
	if view == nil {
		return nil, nil
	}
	se := view.Event
	proc, err := view.matchSubject(scope, authorizedKeysDetection(), r.ID())
	if err != nil || proc == nil {
		return nil, err
	}
	if r.Exclusions != nil && r.Exclusions.Excluded(r.ID(), api.ExclusionMatchPathGlob, proc.Path, evt.HostID) {
		return nil, nil
	}
	target := firstField(se, "TargetFilename")
	description := fmt.Sprintf("%s wrote %s: SSH key persistence (MITRE T1098.004)", proc.Path, target)
	if evt.EventType == "file_rename" {
		description = fmt.Sprintf("%s renamed a file onto %s: SSH key persistence (MITRE T1098.004)", proc.Path, target)
	}
	return &api.Finding{
		HostID:      evt.HostID,
		RuleID:      r.ID(),
		Severity:    api.SeverityMedium,
		Title:       r.DisplayName(),
		Description: description,
		ProcessID:   proc.ID,
		EventIDs:    []string{evt.EventID},
	}, nil
}
