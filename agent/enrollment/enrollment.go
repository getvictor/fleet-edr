// Package enrollment drives the agent side of the Phase 1 identity protocol.
//
//   - Ensure: called once at startup. If a persisted token file exists, loads it. Otherwise,
//     performs a fresh enrollment against the server using EDR_ENROLL_SECRET, persists the
//     result atomically to EDR_TOKEN_FILE (default /var/db/fleet-edr/enrolled.plist), and
//     returns the token + host_id.
//
//   - Token (type TokenProvider): the interface the uploader + commander consume. Returns
//     the current token. On HTTP 401 they call OnUnauthorized, which triggers a re-enroll
//     (rate-limited to at most one attempt per minute) and rotates the token in-place.
//
// Persistence uses XML plist format so operators can inspect the file via `plutil -p`. The
// file is written with mode 0600; loading a world-readable file is a fatal error. Writes
// use write-to-.new + fsync(file) + rename. On APFS (the Phase 1 target) rename is a
// durable metadata op, so this gives us crash safety; see writePersisted for details if you
// port to a non-APFS filesystem.
package enrollment

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fleetdm/edr/agent/hostid"
)

// Persisted is the on-disk representation of a successful enrollment.
type Persisted struct {
	HostID     string    `plist:"host_id" json:"host_id"`
	HostToken  string    `plist:"host_token" json:"host_token"`
	EnrolledAt time.Time `plist:"enrolled_at" json:"enrolled_at"`
	ServerURL  string    `plist:"server_url" json:"server_url"`
}

// TokenProvider returns the current host token. Callers call Token() on every request and
// OnUnauthorized() when they see an HTTP 401 from the server.
type TokenProvider interface {
	Token() string
	HostID() string
	OnUnauthorized(ctx context.Context)
}

// Options bundle the inputs to Ensure. Populate from agent/config and env.
type Options struct {
	ServerURL         string
	EnrollSecret      string
	TokenFile         string
	ServerFingerprint string // hex SHA-256 of the expected server leaf cert; empty disables pinning
	AllowInsecure     bool   // allow http:// + skip cert verify (dev only)
	HostIDOverride    string // if set, used instead of the IOPlatformUUID
	AgentVersion      string
	Logger            *slog.Logger
}

// Ensure loads an existing token file or performs a fresh enroll. Returns a TokenProvider the
// uploader + commander can share.
func Ensure(ctx context.Context, opts Options) (TokenProvider, error) {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.TokenFile == "" {
		return nil, errors.New("enrollment.Ensure: TokenFile is required")
	}

	p := &provider{
		opts:   opts,
		logger: opts.Logger,
	}

	// Try to load the persisted token first. Happy path on every restart.
	if existing, err := loadPersisted(opts.TokenFile); err == nil {
		// Refuse a token bound to a different server. If EDR_SERVER_URL changed, sending the
		// old host_token to a new endpoint would leak it to whatever server answers; fail loud
		// and make the operator delete the file (or re-enroll with the matching URL) instead.
		if trimTrailingSlash(existing.ServerURL) != trimTrailingSlash(opts.ServerURL) {
			return nil, fmt.Errorf(
				"token file %q is bound to server_url %q but EDR_SERVER_URL is %q; delete the file or re-enroll",
				opts.TokenFile, existing.ServerURL, opts.ServerURL,
			)
		}
		p.state.Store(&persistedState{p: existing})
		opts.Logger.InfoContext(ctx, "loaded persisted token",
			"edr.host_id", existing.HostID, "edr.token_file", opts.TokenFile)
		return p, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		// A file that exists but can't be loaded (bad perms, corrupted, wrong schema) is a hard
		// fail — the operator needs to take action. Silent fallback to enroll would leave a
		// stale token on disk.
		return nil, fmt.Errorf("load token file %q: %w", opts.TokenFile, err)
	}

	// First boot: need EDR_ENROLL_SECRET to call /api/v1/enroll.
	if opts.EnrollSecret == "" {
		return nil, fmt.Errorf(
			"no token file at %q and EDR_ENROLL_SECRET is not set — cannot bootstrap",
			opts.TokenFile,
		)
	}

	if err := p.enroll(ctx); err != nil {
		return nil, fmt.Errorf("first-boot enroll: %w", err)
	}
	return p, nil
}

// --- provider + state types ---

type persistedState struct {
	p *Persisted
}

type provider struct {
	opts   Options
	logger *slog.Logger

	state       atomicState
	reenrollMu  sync.Mutex
	lastAttempt time.Time
}

type atomicState struct{ v atomic.Value }

func (a *atomicState) Load() *persistedState {
	v := a.v.Load()
	if v == nil {
		return nil
	}
	return v.(*persistedState)
}

func (a *atomicState) Store(s *persistedState) { a.v.Store(s) }

func (p *provider) Token() string {
	s := p.state.Load()
	if s == nil || s.p == nil {
		return ""
	}
	return s.p.HostToken
}

func (p *provider) HostID() string {
	s := p.state.Load()
	if s == nil || s.p == nil {
		return ""
	}
	return s.p.HostID
}

// OnUnauthorized is called by the uploader/commander when the server returns 401. We throttle
// to at most one attempt per minute so a misconfigured server doesn't get spammed. If the
// operator started the agent from a persisted token without EDR_ENROLL_SECRET, re-enroll
// cannot succeed — log a loud error and skip so we don't spin through pointless throttled
// attempts.
func (p *provider) OnUnauthorized(ctx context.Context) {
	p.reenrollMu.Lock()
	defer p.reenrollMu.Unlock()
	if p.opts.EnrollSecret == "" {
		p.logger.ErrorContext(ctx, "reenroll blocked: EDR_ENROLL_SECRET is not set",
			"remedy", "set EDR_ENROLL_SECRET and restart the agent to recover from token revocation",
		)
		return
	}
	if !p.lastAttempt.IsZero() && time.Since(p.lastAttempt) < time.Minute {
		return
	}
	p.lastAttempt = time.Now()
	p.logger.InfoContext(ctx, "reenroll triggered", "reason", "401_from_server")
	if err := p.enroll(ctx); err != nil {
		p.logger.WarnContext(ctx, "reenroll failed", "err", err)
	}
}

// enroll performs the actual /api/v1/enroll call + persist. Thread-safety is the caller's
// responsibility: first-boot is single-threaded from Ensure, re-enrolls hold reenrollMu.
func (p *provider) enroll(ctx context.Context) error {
	hostID := p.opts.HostIDOverride
	if hostID == "" {
		derived, err := hostid.Get(ctx)
		if err != nil {
			return fmt.Errorf("derive host_id: %w", err)
		}
		hostID = derived
	}

	client, err := p.httpClient()
	if err != nil {
		return err
	}

	payload := map[string]string{
		"enroll_secret": p.opts.EnrollSecret,
		"hardware_uuid": hostID,
		"hostname":      hostname(),
		"os_version":    osVersion(),
		"agent_version": p.opts.AgentVersion,
	}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.opts.ServerURL+"/api/v1/enroll",
		bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("post enroll: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("enroll server returned %d: %s", resp.StatusCode, string(b))
	}

	var respBody struct {
		HostID     string    `json:"host_id"`
		HostToken  string    `json:"host_token"`
		EnrolledAt time.Time `json:"enrolled_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&respBody); err != nil {
		return fmt.Errorf("decode enroll response: %w", err)
	}

	persisted := &Persisted{
		HostID:     respBody.HostID,
		HostToken:  respBody.HostToken,
		EnrolledAt: respBody.EnrolledAt,
		ServerURL:  p.opts.ServerURL,
	}
	if err := writePersisted(p.opts.TokenFile, persisted); err != nil {
		return fmt.Errorf("persist token file: %w", err)
	}
	p.state.Store(&persistedState{p: persisted})

	p.logger.InfoContext(ctx, "agent enrolled",
		"edr.enroll.result", "success",
		"edr.host_id", persisted.HostID,
	)
	return nil
}

// httpClient builds an http.Client that honours the fingerprint-pinning + insecure toggles.
// We clone http.DefaultTransport so we inherit the stdlib's dial/idle/keep-alive timeouts and
// ProxyFromEnvironment support — a bare &http.Transport{} loses those, which in turn loses
// HTTPS_PROXY support and can leak connections under load.
func (p *provider) httpClient() (*http.Client, error) {
	tlsCfg, err := BuildTLSConfig(p.opts.AllowInsecure, p.opts.ServerFingerprint, p.logger)
	if err != nil {
		return nil, err
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tlsCfg
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: tr,
	}, nil
}

// BuildTLSConfig returns a *tls.Config that honours the agent's AllowInsecure +
// ServerFingerprint settings. Exposed so the uploader + commander HTTP clients in main.go
// can share the exact same TLS policy as the enrollment client — without this, the
// enrollment round-trip succeeds against a self-signed cert but every subsequent request
// fails with "x509: certificate signed by unknown authority" because DefaultTransport
// doesn't know about the opt-in.
//
// Fingerprint pinning always takes precedence over AllowInsecure. When both are set, the
// pinning verifier still runs — AllowInsecure alone is only the no-fingerprint dev shortcut.
// This matches the operator intuition that fingerprint pinning is the *stronger* guarantee.
func BuildTLSConfig(allowInsecure bool, serverFingerprint string, logger *slog.Logger) (*tls.Config, error) {
	if logger == nil {
		logger = slog.Default()
	}
	tlsCfg := &tls.Config{
		MinVersion:             tls.VersionTLS12,
		SessionTicketsDisabled: true, // ensure VerifyPeerCertificate is always called (no resume).
	}
	if serverFingerprint == "" {
		if allowInsecure {
			tlsCfg.InsecureSkipVerify = true //nolint:gosec // Dev mode, opted-in via EDR_ALLOW_INSECURE=1.
		}
		return tlsCfg, nil
	}
	want, err := parseFingerprint(serverFingerprint)
	if err != nil {
		return nil, fmt.Errorf("parse server fingerprint: %w", err)
	}
	// Fingerprint pinning replaces chain verification, not augments it. We set
	// InsecureSkipVerify so Go's default chain verification is skipped (it would otherwise
	// reject self-signed certs BEFORE reaching VerifyPeerCertificate), then do our own
	// fingerprint-equality check. The callback is guaranteed to run on every handshake
	// because SessionTicketsDisabled above prevents resume.
	tlsCfg.InsecureSkipVerify = true //nolint:gosec // We implement our own verification below.
	tlsCfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("tls: no peer certificates")
		}
		sum := sha256.Sum256(rawCerts[0])
		if !bytesEqual(sum[:], want) {
			logger.WarnContext(context.Background(), "edr.tls.verify",
				"reason", "fingerprint_mismatch",
				"got", hex.EncodeToString(sum[:]),
			)
			return errors.New("tls: server fingerprint mismatch")
		}
		return nil
	}
	return tlsCfg, nil
}

// --- persistence ---

// loadPersisted reads + validates the on-disk token. Mode must be 0600; the file must
// round-trip through our plist schema. Any deviation is a hard error rather than silent
// recovery — the operator needs to either delete the file or fix its perms.
func loadPersisted(path string) (*Persisted, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if mode := st.Mode().Perm(); mode != 0o600 {
		return nil, fmt.Errorf("token file %q has insecure permissions %#o (want 0600)", path, mode)
	}
	buf, err := os.ReadFile(path) //nolint:gosec // Path is operator-controlled via EDR_TOKEN_FILE; no user input.
	if err != nil {
		return nil, err
	}
	// We write plist XML via marshalMinimalPlist; parse that back here. JSON fallback is
	// intentionally not attempted — a malformed file is an operator signal, not something to
	// heuristically recover.
	p, perr := parseMinimalPlist(buf)
	if perr != nil {
		return nil, fmt.Errorf("parse plist: %w", perr)
	}
	if p.HostID == "" || p.HostToken == "" {
		return nil, errors.New("token file missing host_id or host_token")
	}
	return p, nil
}

// writePersisted atomically writes the token file with mode 0600.
//
// We remove any stale .new file before opening with O_EXCL so the temp file is always a fresh
// inode at 0600 — O_TRUNC on an attacker-preseeded .new with broader permissions would briefly
// leak the token. fsync on the file forces data to disk; APFS + ext4-default make the rename
// itself durable, but strict POSIX requires fsyncing the parent directory too. We don't do
// that here because macOS doesn't expose a reliable cross-volume directory fsync and the MVP
// target platforms (APFS) treat rename as a transactional metadata op already. If we ever
// port the agent to a non-APFS Linux filesystem, revisit.
func writePersisted(path string, p *Persisted) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	buf := marshalMinimalPlist(p)
	tmp := path + ".new"
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) //nolint:gosec // operator-controlled path via EDR_TOKEN_FILE.
	if err != nil {
		return err
	}
	if _, err := f.Write(buf); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// trimTrailingSlash strips a single trailing "/" so "https://a.example/" and
// "https://a.example" compare equal when validating the persisted ServerURL.
func trimTrailingSlash(s string) string {
	return strings.TrimSuffix(s, "/")
}

// --- minimal plist codec ---
//
// We avoid pulling in a plist dep for MVP by hand-rolling an XML encoder/decoder for the
// flat dict we care about. The output is valid XML plist that `plutil -p` understands.

func marshalMinimalPlist(p *Persisted) []byte {
	var buf bytes.Buffer
	buf.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	buf.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
	buf.WriteString(`<plist version="1.0"><dict>` + "\n")
	writePlistString(&buf, "host_id", p.HostID)
	writePlistString(&buf, "host_token", p.HostToken)
	writePlistString(&buf, "server_url", p.ServerURL)
	writePlistDate(&buf, "enrolled_at", p.EnrolledAt)
	buf.WriteString(`</dict></plist>` + "\n")
	return buf.Bytes()
}

func writePlistString(w *bytes.Buffer, k, v string) {
	fmt.Fprintf(w, "  <key>%s</key><string>%s</string>\n", xmlEscape(k), xmlEscape(v))
}

func writePlistDate(w *bytes.Buffer, k string, t time.Time) {
	fmt.Fprintf(w, "  <key>%s</key><date>%s</date>\n", xmlEscape(k), t.UTC().Format(time.RFC3339))
}

func xmlEscape(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// parseMinimalPlist pulls the four keys we care about out of the XML via a tag-by-tag walk.
// Intentionally simple: no nested dicts, no arrays, no numbers.
func parseMinimalPlist(buf []byte) (*Persisted, error) {
	dec := xml.NewDecoder(bytes.NewReader(buf))
	p := &Persisted{}
	var key string
	for {
		tok, err := dec.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		if err := applyPlistElement(dec, se, &key, p); err != nil {
			return nil, err
		}
	}
	return p, nil
}

// applyPlistElement decodes a single XML element into the Persisted struct, mutating
// *keyPtr to track the "key" token preceding each value. Extracted from
// parseMinimalPlist so the driver loop stays flat.
func applyPlistElement(dec *xml.Decoder, se xml.StartElement, keyPtr *string, p *Persisted) error {
	switch se.Name.Local {
	case "key":
		var k string
		if err := dec.DecodeElement(&k, &se); err != nil {
			return err
		}
		*keyPtr = k
	case "string":
		var v string
		if err := dec.DecodeElement(&v, &se); err != nil {
			return err
		}
		switch *keyPtr {
		case "host_id":
			p.HostID = v
		case "host_token":
			p.HostToken = v
		case "server_url":
			p.ServerURL = v
		}
		*keyPtr = ""
	case "date":
		var v string
		if err := dec.DecodeElement(&v, &se); err != nil {
			return err
		}
		if *keyPtr == "enrolled_at" {
			if t, err := time.Parse(time.RFC3339, strings.TrimSpace(v)); err == nil {
				p.EnrolledAt = t
			}
		}
		*keyPtr = ""
	}
	return nil
}

// --- tiny helpers ---

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return h
}

func osVersion() string {
	return runtime.GOOS
}

func parseFingerprint(s string) ([]byte, error) {
	s = strings.TrimPrefix(s, "sha256:")
	s = strings.ReplaceAll(s, ":", "")
	s = strings.TrimSpace(s)
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != sha256.Size {
		return nil, fmt.Errorf("fingerprint must be %d bytes (got %d)", sha256.Size, len(b))
	}
	return b, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
