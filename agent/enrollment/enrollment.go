// Package enrollment drives the agent side of the host-identity protocol.
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
// use write-to-.new + fsync(file) + rename. On APFS (the macOS target) rename is a
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

const (
	// tokenFileMode is the required Unix mode for the persisted token file. 0600 keeps the bearer token readable only by root; loading a
	// more permissive file is a hard error so a misconfigured umask never silently becomes a credential exposure.
	tokenFileMode os.FileMode = 0o600

	// enrollErrorBodyLimit caps how much of an enrollment-error response body we read into a returned error string. The server is trusted;
	// the cap is belt-and-braces against an unexpectedly large 5xx body.
	enrollErrorBodyLimit = 2048

	// logAttrHostID is the structured-log attribute key for the agent's persisted host_id. Centralised so a key rename propagates
	// uniformly to operator log dashboards.
	logAttrHostID = "edr.host_id"

	// refreshCheckInterval is how often the proactive refresh loop checks whether the current token is within its refresh window. The
	// window itself is two-thirds of the token lifetime, so a one-minute check is ample granularity for a 60-minute token.
	refreshCheckInterval = time.Minute
)

// Persisted is the on-disk representation of a successful enrollment.
type Persisted struct {
	HostID     string    `plist:"host_id" json:"host_id"`
	HostToken  string    `plist:"host_token" json:"host_token"`
	ExpiresAt  time.Time `plist:"expires_at" json:"expires_at"`
	EnrolledAt time.Time `plist:"enrolled_at" json:"enrolled_at"`
	ServerURL  string    `plist:"server_url" json:"server_url"`
}

// TokenProvider returns the current host token. Callers call Token() on every request and OnUnauthorized() when they see an HTTP 401
// from the server. Rotate replaces the in-memory + on-disk token atomically; the commander's rotate_token dispatch (issue #86) is the
// only caller in production. A nil error means subsequent Token() calls observe the new value, even if the agent crashes mid-write
// (writePersisted is atomic-via-rename).
type TokenProvider interface {
	Token() string
	HostID() string
	OnUnauthorized(ctx context.Context)
	Rotate(ctx context.Context, newToken string) error
}

// Refresher is implemented by the concrete provider to run the proactive token-refresh loop. It is an optional interface (the agent
// type-asserts the TokenProvider to it) so test doubles that don't need refresh stay minimal. RunRefresh blocks until ctx is cancelled.
type Refresher interface {
	RunRefresh(ctx context.Context)
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
		// Refuse a token bound to a different server. If EDR_SERVER_URL changed, sending the old host_token to a new endpoint
		// would leak it to whatever server answers; fail loud and make the operator delete the file (or re-enroll with the
		// matching URL) instead.
		if trimTrailingSlash(existing.ServerURL) != trimTrailingSlash(opts.ServerURL) {
			return nil, fmt.Errorf(
				"token file %q is bound to server_url %q but EDR_SERVER_URL is %q; delete the file or re-enroll",
				opts.TokenFile, existing.ServerURL, opts.ServerURL,
			)
		}
		p.state.Store(&persistedState{p: existing, refreshAt: computeRefreshAt(time.Now(), existing.ExpiresAt)})
		opts.Logger.InfoContext(ctx, "loaded persisted token",
			logAttrHostID, existing.HostID, "edr.token_file", opts.TokenFile)
		return p, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		// A file that exists but can't be loaded (bad perms, corrupted, wrong schema) is a hard fail: the operator needs to
		// take action. Silent fallback to enroll would leave a stale token on disk.
		return nil, fmt.Errorf("load token file %q: %w", opts.TokenFile, err)
	}

	// First boot: need EDR_ENROLL_SECRET to call /api/enroll.
	if opts.EnrollSecret == "" {
		return nil, fmt.Errorf(
			"no token file at %q and EDR_ENROLL_SECRET is not set: cannot bootstrap",
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
	// refreshAt is when the proactive refresh loop should renew this token: two-thirds through its remaining lifetime at the moment it
	// was received or loaded. Zero means "no proactive refresh" (legacy token with no expiry, or already expired).
	refreshAt time.Time
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

// Rotate replaces the persisted bearer token with newToken atomically (write to a temp file + rename). Subsequent Token() calls return
// the new value. The provider's same reenrollMu serialises Rotate against any concurrent re-enroll so a 401-driven re-enroll and a
// server-driven rotate cannot interleave their writes. Returns an error when newToken is empty (a programmer error, surfaced loudly),
// when there is no persisted state to rotate from (the agent never enrolled), or when the on-disk write fails.
func (p *provider) Rotate(ctx context.Context, newToken string) error {
	if newToken == "" {
		return errors.New("enrollment.Rotate: empty token")
	}
	p.reenrollMu.Lock()
	defer p.reenrollMu.Unlock()

	cur := p.state.Load()
	if cur == nil || cur.p == nil {
		return errors.New("enrollment.Rotate: no persisted state to rotate from")
	}
	next := *cur.p
	next.HostToken = newToken
	if err := writePersisted(p.opts.TokenFile, &next); err != nil {
		return fmt.Errorf("persist rotated token: %w", err)
	}
	p.state.Store(&persistedState{p: &next, refreshAt: computeRefreshAt(time.Now(), next.ExpiresAt)})
	p.logger.InfoContext(ctx, "agent token rotated", logAttrHostID, next.HostID)
	return nil
}

// OnUnauthorized is called by the uploader/commander when the server returns 401. We throttle to at most one attempt per minute so
// a misconfigured server doesn't get spammed. If the operator started the agent from a persisted token without EDR_ENROLL_SECRET,
// re-enroll cannot succeed: log a loud error and skip so we don't spin through pointless throttled attempts.
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

// computeRefreshAt returns when the agent should proactively refresh a token expiring at exp, given the current time now: two-thirds of
// the way through the remaining lifetime. A zero or already-past exp returns the zero time, which the refresh loop treats as "no
// proactive refresh" (a legacy token with no expiry that will 401 and re-enroll, or an already-expired one).
func computeRefreshAt(now, exp time.Time) time.Time {
	if exp.IsZero() || !exp.After(now) {
		return time.Time{}
	}
	return now.Add(exp.Sub(now) * 2 / 3)
}

// RunRefresh runs the proactive token-refresh loop until ctx is cancelled. Each tick it checks whether the current token has entered
// its refresh window (computeRefreshAt) and, if so, calls POST /api/token/refresh to mint a fresh token before the current one expires,
// so a live agent never lapses without a full re-enroll. Refresh uses only the current token (no enroll secret), so it works even on a
// host that has no EDR_ENROLL_SECRET on disk.
func (p *provider) RunRefresh(ctx context.Context) {
	// Check immediately on entry, not only on the first tick: an agent that just started or resumed from sleep may already hold a token
	// past its refresh point (or within a tick of expiry). Waiting a full refreshCheckInterval could let it expire first, after which
	// even /api/token/refresh 401s and recovery needs the enroll secret. Then check on every tick.
	p.maybeRefresh(ctx)
	ticker := time.NewTicker(refreshCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.maybeRefresh(ctx)
		}
	}
}

// maybeRefresh refreshes the token if it has entered its refresh window (computeRefreshAt has passed). A no-op otherwise; safe to call
// repeatedly from both the immediate-entry check and the ticker.
func (p *provider) maybeRefresh(ctx context.Context) {
	st := p.state.Load()
	if st == nil || st.p == nil || st.refreshAt.IsZero() || time.Now().Before(st.refreshAt) {
		return
	}
	if err := p.refreshOnce(ctx); err != nil {
		p.logger.WarnContext(ctx, "token refresh failed", "err", err)
	}
}

// refreshOnce performs one POST /api/token/refresh round-trip and swaps in the returned token. A 401 means the token was revoked or
// otherwise rejected: fall back to the re-enroll path (which needs EDR_ENROLL_SECRET) rather than spinning on a dead token.
func (p *provider) refreshOnce(ctx context.Context) error {
	cur := p.state.Load()
	if cur == nil || cur.p == nil {
		return errors.New("refresh: no persisted token")
	}
	client, err := p.httpClient() //nolint:contextcheck // httpClient is pure config assembly; see enroll's identical call.
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.opts.ServerURL+"/api/token/refresh", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+cur.p.HostToken)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("post refresh: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		p.logger.WarnContext(ctx, "token refresh unauthorized; re-enrolling", logAttrHostID, cur.p.HostID)
		p.OnUnauthorized(ctx)
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, enrollErrorBodyLimit))
		return fmt.Errorf("refresh server returned %d: %s", resp.StatusCode, string(b))
	}
	var body struct {
		HostToken string    `json:"host_token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return fmt.Errorf("decode refresh response: %w", err)
	}
	if body.HostToken == "" {
		return errors.New("refresh: empty token in response")
	}
	return p.applyRefresh(ctx, body.HostToken, body.ExpiresAt)
}

// applyRefresh atomically swaps the persisted token + expiry to the refreshed values (write-to-temp + rename), mirroring Rotate but
// also carrying the new expiry so the refresh loop reschedules. Serialised against re-enroll / rotate via reenrollMu.
func (p *provider) applyRefresh(ctx context.Context, newToken string, exp time.Time) error {
	p.reenrollMu.Lock()
	defer p.reenrollMu.Unlock()
	cur := p.state.Load()
	if cur == nil || cur.p == nil {
		return errors.New("applyRefresh: no persisted state")
	}
	next := *cur.p
	next.HostToken = newToken
	next.ExpiresAt = exp
	if err := writePersisted(p.opts.TokenFile, &next); err != nil {
		return fmt.Errorf("persist refreshed token: %w", err)
	}
	p.state.Store(&persistedState{p: &next, refreshAt: computeRefreshAt(time.Now(), exp)})
	p.logger.InfoContext(ctx, "host token refreshed", logAttrHostID, next.HostID, "edr.token.expires_at", exp)
	return nil
}

// enroll performs the actual /api/enroll call + persist. Thread-safety is the caller's
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

	// httpClient() is pure config assembly (TLS options + http.Client struct). It takes no context because it does no I/O or cancellable
	// work, so the contextcheck traversal through BuildTLSConfig's VerifyPeerCertificate closure is a known false positive.
	client, err := p.httpClient() //nolint:contextcheck // see comment above.
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

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.opts.ServerURL+"/api/enroll",
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
		b, _ := io.ReadAll(io.LimitReader(resp.Body, enrollErrorBodyLimit))
		return fmt.Errorf("enroll server returned %d: %s", resp.StatusCode, string(b))
	}

	var respBody struct {
		HostID     string    `json:"host_id"`
		HostToken  string    `json:"host_token"`
		EnrolledAt time.Time `json:"enrolled_at"`
		ExpiresAt  time.Time `json:"expires_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&respBody); err != nil {
		return fmt.Errorf("decode enroll response: %w", err)
	}

	persisted := &Persisted{
		HostID:     respBody.HostID,
		HostToken:  respBody.HostToken,
		ExpiresAt:  respBody.ExpiresAt,
		EnrolledAt: respBody.EnrolledAt,
		ServerURL:  p.opts.ServerURL,
	}
	if err := writePersisted(p.opts.TokenFile, persisted); err != nil {
		return fmt.Errorf("persist token file: %w", err)
	}
	p.state.Store(&persistedState{p: persisted, refreshAt: computeRefreshAt(time.Now(), persisted.ExpiresAt)})

	p.logger.InfoContext(ctx, "agent enrolled",
		"edr.enroll.result", "success",
		logAttrHostID, persisted.HostID,
	)
	return nil
}

// httpClient builds an http.Client that honours the fingerprint-pinning + insecure toggles. We clone http.DefaultTransport so we
// inherit the stdlib's dial/idle/keep-alive timeouts and ProxyFromEnvironment support. A bare &http.Transport{} loses those, which in
// turn loses HTTPS_PROXY support and can leak connections under load.
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
// can share the exact same TLS policy as the enrollment client. Without this, the
// enrollment round-trip succeeds against a self-signed cert but every subsequent request
// fails with "x509: certificate signed by unknown authority" because DefaultTransport
// doesn't know about the opt-in.
//
// Fingerprint pinning always takes precedence over AllowInsecure. When both are set, the
// pinning verifier still runs: AllowInsecure alone is only the no-fingerprint dev shortcut.
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
	// Fingerprint pinning replaces chain verification, not augments it. We set InsecureSkipVerify so Go's default chain verification is
	// skipped (it would otherwise reject self-signed certs BEFORE reaching VerifyPeerCertificate), then do our own fingerprint-equality
	// check. The callback is guaranteed to run on every handshake because SessionTicketsDisabled above prevents resume.
	tlsCfg.InsecureSkipVerify = true //nolint:gosec // We implement our own verification below.
	// VerifyPeerCertificate is invoked by the TLS stack during the handshake with no request context available, so the warn log here
	// intentionally uses context.Background().
	tlsCfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error { //nolint:contextcheck // see comment above.
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

// loadPersisted reads + validates the on-disk token. Mode must be 0600; the file must round-trip through our plist schema. Any
// deviation is a hard error rather than silent recovery: the operator needs to either delete the file or fix its perms.
func loadPersisted(path string) (*Persisted, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if mode := st.Mode().Perm(); mode != tokenFileMode {
		return nil, fmt.Errorf("token file %q has insecure permissions %#o (want %#o)", path, mode, tokenFileMode)
	}
	buf, err := os.ReadFile(path) //nolint:gosec // Path is operator-controlled via EDR_TOKEN_FILE; no user input.
	if err != nil {
		return nil, err
	}
	// We write plist XML via marshalMinimalPlist; parse that back here. JSON fallback is intentionally not attempted: a malformed file is
	// an operator signal, not something to heuristically recover.
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
// inode at 0600: O_TRUNC on an attacker-preseeded .new with broader permissions would briefly
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
	writePlistDate(&buf, "expires_at", p.ExpiresAt)
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

// applyPlistElement decodes a single XML element into the Persisted struct, mutating *keyPtr to track the "key" token preceding each
// value. Extracted from parseMinimalPlist so the driver loop stays flat.
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
		if t, err := time.Parse(time.RFC3339, strings.TrimSpace(v)); err == nil {
			switch *keyPtr {
			case "enrolled_at":
				p.EnrolledAt = t
			case "expires_at":
				p.ExpiresAt = t
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
