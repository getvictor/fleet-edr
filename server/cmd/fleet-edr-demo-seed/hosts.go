package main

import (
	"bufio"
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"time"

	"github.com/fleetdm/edr/test/fakeagent"
)

// hostCorpusFS holds the rich, real-captured host streams replayed into the demo. Each file is a scrubbed JSONL export of an
// edr-qa agent event queue (one fakeagent.Envelope per line: the same wire shape /api/events receives). These supply the deep,
// realistic process trees with correlated network_connect + dns_query that the attack/noise YAML scenarios lack; the scrub
// (ai/demo/scrub.py) dropped heartbeats, remapped the host UUID, mapped real IPs to RFC 5737 / RFC 3849 documentation ranges
// (consistently, so the DNS -> network correlation survives), and redacted identity strings.
//
//go:embed corpus/hosts/*.jsonl
var hostCorpusFS embed.FS

// hostReplayBatchSize is how many captured envelopes are POSTed per /api/events request. Captured hosts carry hundreds to low
// thousands of events; batching keeps each request small while still draining the stream in a handful of round trips.
const hostReplayBatchSize = 500

// recentTailOffset is how far before "now" the latest captured event is placed when the stream is shifted to look recent. A small
// gap keeps every event in the past (never future-dated) while the graph still reads as "just now."
const recentTailOffset = time.Minute

// maxHostCorpusLineBytes caps a single JSONL line. dns_query response_addresses lists can push a line past bufio.Scanner's 64 KiB
// default; 1 MiB is comfortably above any single captured envelope.
const maxHostCorpusLineBytes = 1 << 20

// attackPIDOffsetBase and attackPIDOffsetStride keep a woven attack's pids from colliding with the captured host's pids (which
// top out in the low five figures) or with another attack woven onto the same host. Each attack on a host is offset by
// base + index*stride; launchd/kernel sentinels (<= 1) are preserved so the attack subtree still roots at pid 1.
const (
	attackPIDOffsetBase   = 5_000_000
	attackPIDOffsetStride = 100_000
	// attackStagger spaces successive woven attacks apart in time so each reads as a distinct event in the host's timeline.
	attackStagger = 2 * time.Second
)

// wovenAttack is an attack scenario re-hosted onto a captured host: the same fakeagent YAML the efficacy corpus uses, but its
// pids are offset and its host_id is overridden to the captured host so the detection fires inside real ambient activity.
type wovenAttack struct {
	File       string       // under corpus/
	Kind       scenarioKind // kindAttack or kindAppControl
	ExpectRule string       // the catalog rule this attack should trip (documentation; verify asserts the alert count)
}

// demoHost is a rich, real-captured host: a deep process tree with correlated network_connect + dns_query, scrubbed from an
// edr-qa capture, with attacks woven in so the detections fire inside genuine ambient activity (the plan's "fewer hosts, attacks
// in context"). Distinct from a stub 2-event attack host.
type demoHost struct {
	File     string // captured stream under corpus/hosts/
	Hostname string
	Attacks  []wovenAttack // attacks re-hosted onto this host
}

// hostManifest is the ordered set of rich captured hosts and the attacks woven onto each. Order is replay order and the order
// hosts appear in the demo UI. Two real hosts cover all five detections: the engineer laptop carries credential theft + a DNS C2
// beacon; the build server carries persistence, privilege escalation, and a blocked binary.
var hostManifest = []demoHost{
	{File: "alex-mbp.jsonl", Hostname: "alex-mbp.local", Attacks: []wovenAttack{
		{File: "keychain-dump.yaml", Kind: kindAttack, ExpectRule: "credential_keychain_dump"},
		{File: "dns-c2-beacon.yaml", Kind: kindAttack, ExpectRule: "dns_c2_beacon"},
	}},
	{File: "ci-builder.jsonl", Hostname: "ci-builder.local", Attacks: []wovenAttack{
		{File: "sudoers-tamper.yaml", Kind: kindAttack, ExpectRule: "sudoers_tamper"},
		{File: "launchagent-persistence.yaml", Kind: kindAttack, ExpectRule: "persistence_launchagent"},
		{File: "app-control-blocked-app.yaml", Kind: kindAppControl},
	}},
}

// loadHostEnvelopes parses a host's scrubbed JSONL capture into wire envelopes and returns them with the host_id they all carry.
// The lines are already fakeagent.Envelope-shaped, so this is a direct per-line decode. It verifies every line shares one host_id
// (the scrub stamps a single demo UUID per file) so a mis-scrubbed file fails loudly rather than enrolling a phantom host.
func loadHostEnvelopes(file string) ([]fakeagent.Envelope, string, error) {
	raw, err := fs.ReadFile(hostCorpusFS, "corpus/hosts/"+file)
	if err != nil {
		return nil, "", fmt.Errorf("read host corpus %s: %w", file, err)
	}
	return decodeHostEnvelopes(raw, file)
}

// decodeHostEnvelopes parses a scrubbed JSONL capture into wire envelopes and returns them with the single host_id they all
// carry. Split from the embed read so the malformed-line / mixed-host / empty failure paths are unit-testable without a
// checked-in bad fixture.
func decodeHostEnvelopes(raw []byte, file string) ([]fakeagent.Envelope, string, error) {
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 0, maxHostCorpusLineBytes), maxHostCorpusLineBytes)
	var envs []fakeagent.Envelope
	hostID := ""
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var env fakeagent.Envelope
		if err := json.Unmarshal(line, &env); err != nil {
			return nil, "", fmt.Errorf("parse host corpus %s: %w", file, err)
		}
		if hostID == "" {
			hostID = env.HostID
		} else if env.HostID != hostID {
			return nil, "", fmt.Errorf("host corpus %s mixes host_ids (%s vs %s)", file, hostID, env.HostID)
		}
		envs = append(envs, env)
	}
	if err := scanner.Err(); err != nil {
		return nil, "", fmt.Errorf("scan host corpus %s: %w", file, err)
	}
	if len(envs) == 0 {
		return nil, "", fmt.Errorf("host corpus %s is empty", file)
	}
	return envs, hostID, nil
}

// demoHostIDs returns the captured host UUID of every manifest host. refreshTimestamps scopes its UPDATEs to these so a
// mis-pointed DSN can only ever shift the demo's own rows: the seeder takes an operator-supplied DSN and the already-seeded check
// keys on a real production rule id (credential_keychain_dump), so without this scope the refresh could rewrite a real
// deployment's timelines.
func demoHostIDs() ([]string, error) {
	ids := make([]string, 0, len(hostManifest))
	for _, h := range hostManifest {
		_, hostID, err := loadHostEnvelopes(h.File)
		if err != nil {
			return nil, fmt.Errorf("load host ids %s: %w", h.File, err)
		}
		ids = append(ids, hostID)
	}
	return ids, nil
}

// shiftEnvelopesToRecent rewrites every envelope's timestamp so the latest event lands recentTailOffset before now, preserving the
// inter-event deltas of the original capture. This makes the replayed graph read as recent activity without compressing the
// timeline, so the UI's time structure and the per-process event ordering stay faithful to the real capture. Returns the input
// unchanged when empty. The capture's timestamps are device-clock nanoseconds; shifting by a constant preserves all relative order.
func shiftEnvelopesToRecent(envs []fakeagent.Envelope, now time.Time) []fakeagent.Envelope {
	if len(envs) == 0 {
		return envs
	}
	maxTS := envs[0].TimestampNs
	for _, e := range envs {
		if e.TimestampNs > maxTS {
			maxTS = e.TimestampNs
		}
	}
	delta := now.Add(-recentTailOffset).UnixNano() - maxTS
	for i := range envs {
		envs[i].TimestampNs += delta
	}
	return envs
}

// replayHost enrols a rich captured host and posts its scrubbed event stream (timestamp-shifted to recent) to the ingest API in
// batches. No app-control / attack weaving here: these hosts are the realistic ambient activity the detection scenarios sit in.
func (s *seeder) replayHost(ctx context.Context, host demoHost) error {
	envs, hostID, err := loadHostEnvelopes(host.File)
	if err != nil {
		return err
	}
	token, err := s.enroll(ctx, hostID, host.Hostname)
	if err != nil {
		return err
	}
	// Anchor woven attacks under a real process from this capture (a shell) so their alerts read as commands run in a session
	// nested in the host's genuine tree, not lone processes hanging off launchd. Derived from the captured pids, so it survives a
	// corpus re-scrub; 0 when the capture has no shell, in which case the attacks keep their launchd root.
	anchorPID := pickAttackAnchorPID(envs)

	// One clock read for the whole host: the ambient tail and every woven attack are placed relative to this same now, so
	// per-batch network latency cannot drift the attacks forward relative to the ambient events (deterministic relative timing).
	now := time.Now()
	shiftEnvelopesToRecent(envs, now)
	for start := 0; start < len(envs); start += hostReplayBatchSize {
		end := min(start+hostReplayBatchSize, len(envs))
		if err := s.postEnvelopes(ctx, token, envs[start:end]); err != nil {
			return fmt.Errorf("post host %s batch [%d:%d]: %w", host.File, start, end, err)
		}
	}
	s.logger.InfoContext(ctx, "replayed captured host",
		"file", host.File, "host_id", hostID, "hostname", host.Hostname, "events", len(envs), "attack_anchor_pid", anchorPID)

	for i, atk := range host.Attacks {
		if err := s.weaveAttack(ctx, hostID, token, atk, i, now, anchorPID); err != nil {
			return fmt.Errorf("weave %s onto %s: %w", atk.File, host.File, err)
		}
	}
	return nil
}

// interactiveShellExecs are the captured exec paths a woven attack is re-parented under, so its alert reads as "commands run in a
// shell" instead of a lone process hanging off launchd. Matched against the captured host stream, never the attack scenario.
var interactiveShellExecs = map[string]bool{
	"/bin/zsh":  true,
	"/bin/bash": true,
	"/bin/sh":   true,
}

// pickAttackAnchorPID returns the pid of the most recent interactive-shell exec in a captured host stream, to use as the parent of
// the attacks woven onto that host (see reparentAttackToHost). Selection is by the event's TimestampNs, not file order: the scrubbed
// captures are not stored time-sorted, so the last line is not necessarily the latest event. Sentinel pids (<= 1) are never chosen.
// Returns 0 when the capture has no shell, leaving the attacks rooted at launchd.
func pickAttackAnchorPID(envs []fakeagent.Envelope) int {
	anchor := 0
	var anchorTS int64
	for i := range envs {
		if envs[i].EventType != "exec" {
			continue
		}
		var p struct {
			PID  int    `json:"pid"`
			Path string `json:"path"`
		}
		if err := json.Unmarshal(envs[i].Payload, &p); err != nil {
			continue
		}
		// >= keeps the later-in-file entry on a timestamp tie, a deterministic tiebreak against the fixed embedded corpus.
		if interactiveShellExecs[p.Path] && p.PID > 1 && (anchor == 0 || envs[i].TimestampNs >= anchorTS) {
			anchor, anchorTS = p.PID, envs[i].TimestampNs
		}
	}
	return anchor
}

// reparentAttackToHost re-points the woven attack's launchd-rooted top (the events still referencing the pid-1 sentinel after
// offsetScenarioPIDs) at a real captured process, so the attack hangs off the host's genuine process tree instead of floating as a
// lone subtree under launchd. anchorPID is a captured pid (a shell, see pickAttackAnchorPID); a value <= 1 means no anchor was
// found and the attack keeps its launchd root. The catalog rules these attacks trip match on exec path/args, never on ppid, so the
// re-parent changes the tree shape the analyst sees without affecting whether the detection fires.
func reparentAttackToHost(sc *fakeagent.Scenario, anchorPID int) {
	if anchorPID <= 1 {
		return
	}
	for i := range sc.Timeline {
		ev := &sc.Timeline[i]
		if ev.PPID == 1 {
			ev.PPID = anchorPID
		}
		if ev.ParentPID == 1 {
			ev.ParentPID = anchorPID
		}
	}
}

// weaveAttack re-hosts an attack scenario onto a captured host: it offsets the scenario's pids (so they can't collide with the
// captured stream or another woven attack), re-parents the attack's root onto a real captured process (anchorPID, a shell) so it
// nests in the host's genuine tree instead of rooting at launchd, overrides the host_id to the captured host, and posts the events
// at a recent, per-attack-staggered time. For an app-control scenario it then posts the fabricated block event against the offset
// pid (after the process materialises), exactly as the standalone path used to.
func (s *seeder) weaveAttack(ctx context.Context, hostID, token string, atk wovenAttack, idx int, now time.Time, anchorPID int) error {
	sc, err := loadAttackScenario(atk.File)
	if err != nil {
		return err
	}
	offsetScenarioPIDs(sc, attackPIDOffsetBase+idx*attackPIDOffsetStride)
	reparentAttackToHost(sc, anchorPID)

	// Place the attack just before the captured tail, staggered per attack, so it reads as recent activity on the host. now is
	// the caller's single clock read (see replayHost) so the attack's offset from the ambient tail stays stable across replays.
	atkStart := now.Add(-recentTailOffset).Add(-time.Duration(idx+1) * attackStagger)
	envs, err := sc.Envelopes(fakeagent.WithStartTime(atkStart), fakeagent.WithHostID(hostID))
	if err != nil {
		return fmt.Errorf("materialise %s: %w", atk.File, err)
	}
	if err := s.postEnvelopes(ctx, token, envs); err != nil {
		return fmt.Errorf("post %s events: %w", atk.File, err)
	}
	s.logger.InfoContext(ctx, "wove attack onto host",
		"file", atk.File, "host_id", hostID, "rule", atk.ExpectRule, "kind", string(atk.Kind), "events", len(envs))

	if atk.Kind != kindAppControl {
		return nil
	}
	pid, execPath, ok := firstExec(sc)
	if !ok {
		return fmt.Errorf("app-control scenario %s has no exec event", atk.File)
	}
	if err := s.waitForProcess(ctx, hostID, pid); err != nil {
		return fmt.Errorf("app-control process pid %d never materialised: %w", pid, err)
	}
	// Stamp the block one second past the scenario start so it sits after the fork/exec; the scenario emits no exit, so the
	// live process resolves at this timestamp.
	blockTS := atkStart.Add(time.Second).UnixNano()
	if err := s.postEnvelopes(ctx, token, []fakeagent.Envelope{buildBlockEnvelope(hostID, pid, execPath, blockTS)}); err != nil {
		return fmt.Errorf("post application_control_block for %s: %w", atk.File, err)
	}
	s.logger.InfoContext(ctx, "posted application-control block", "host_id", hostID, "pid", pid, "path", execPath)
	return nil
}

// offsetScenarioPIDs bumps every pid field in the scenario's timeline by offset, preserving kernel/launchd sentinels (values
// <= 1) so the attack subtree still roots at pid 1. Mutates the scenario in place; callers pass a freshly loaded copy.
func offsetScenarioPIDs(sc *fakeagent.Scenario, offset int) {
	bump := func(p int) int {
		if p > 1 {
			return p + offset
		}
		return p
	}
	for i := range sc.Timeline {
		ev := &sc.Timeline[i]
		ev.PID = bump(ev.PID)
		ev.PPID = bump(ev.PPID)
		ev.ChildPID = bump(ev.ChildPID)
		ev.ParentPID = bump(ev.ParentPID)
		ev.InstigatorPID = bump(ev.InstigatorPID)
	}
}
