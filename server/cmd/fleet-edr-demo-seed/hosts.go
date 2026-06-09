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

// demoHost is a rich, real-captured host: a deep process tree with correlated network_connect + dns_query, scrubbed from an
// edr-qa capture. Distinct from the attack/noise YAML scenarios; these are the ambient activity a real busy Mac produces.
type demoHost struct {
	File     string // under corpus/hosts/
	Hostname string
}

// hostManifest is the ordered set of rich captured hosts. Order is replay order and the order they appear in the demo UI.
var hostManifest = []demoHost{
	{File: "alex-mbp.jsonl", Hostname: "alex-mbp.local"},
	{File: "ci-builder.jsonl", Hostname: "ci-builder.local"},
}

// loadHostEnvelopes parses a host's scrubbed JSONL capture into wire envelopes and returns them with the host_id they all carry.
// The lines are already fakeagent.Envelope-shaped, so this is a direct per-line decode. It verifies every line shares one host_id
// (the scrub stamps a single demo UUID per file) so a mis-scrubbed file fails loudly rather than enrolling a phantom host.
func loadHostEnvelopes(file string) ([]fakeagent.Envelope, string, error) {
	raw, err := fs.ReadFile(hostCorpusFS, "corpus/hosts/"+file)
	if err != nil {
		return nil, "", fmt.Errorf("read host corpus %s: %w", file, err)
	}
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

// shiftEnvelopesToRecent rewrites every envelope's timestamp so the latest event lands at (now - recentTailOffset), preserving the
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
	shiftEnvelopesToRecent(envs, time.Now())
	for start := 0; start < len(envs); start += hostReplayBatchSize {
		end := min(start+hostReplayBatchSize, len(envs))
		if err := s.postEnvelopes(ctx, token, envs[start:end]); err != nil {
			return fmt.Errorf("post host %s batch [%d:%d]: %w", host.File, start, end, err)
		}
	}
	s.logger.InfoContext(ctx, "replayed captured host",
		"file", host.File, "host_id", hostID, "hostname", host.Hostname, "events", len(envs))
	return nil
}
