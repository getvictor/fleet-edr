package breakglass

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// WebAuthnOptions configures the relying-party metadata WebAuthn
// requires at construction time. RPID is the canonical RP identifier
// (typically the registrable host part of RPOrigin without a scheme:
// "edr.example.com"); the browser binds credentials to this id, so
// changing it post-deployment invalidates every registered
// credential. RPDisplayName is operator-visible during enrollment.
// RPOrigins enumerate the schemes+hosts the RP accepts in the
// authenticator's origin attestation; per spec, the production list
// is the externally reachable HTTPS URL of the EDR UI, plus any
// localhost variants used during development.
type WebAuthnOptions struct {
	RPID          string
	RPDisplayName string
	RPOrigins     []string
}

// NewWebAuthn constructs the go-webauthn engine. Errors when any
// required field is empty so a misconfigured deployment refuses to
// start rather than silently issuing challenges that no browser will
// accept.
func NewWebAuthn(opts WebAuthnOptions) (*webauthn.WebAuthn, error) {
	if strings.TrimSpace(opts.RPID) == "" {
		return nil, errors.New("breakglass: WebAuthn RPID is required")
	}
	if strings.TrimSpace(opts.RPDisplayName) == "" {
		return nil, errors.New("breakglass: WebAuthn RPDisplayName is required")
	}
	if len(opts.RPOrigins) == 0 {
		return nil, errors.New("breakglass: WebAuthn RPOrigins is required (at least one absolute URL)")
	}
	for _, origin := range opts.RPOrigins {
		if _, err := url.Parse(origin); err != nil {
			return nil, fmt.Errorf("breakglass: WebAuthn RPOrigins[%q] is not a valid URL: %w", origin, err)
		}
	}
	cfg := &webauthn.Config{
		RPID:          opts.RPID,
		RPDisplayName: opts.RPDisplayName,
		RPOrigins:     opts.RPOrigins,
		// AttestationPreference: indirect — accept anonymized CA
		// attestation (matches the Apple platform authenticator
		// default) but allow direct for hardware keys that prefer
		// it. This balances "operator can see authenticator
		// brand" against "platform authenticators that refuse
		// direct attestation work".
		AttestationPreference: protocol.PreferIndirectAttestation,
		// AuthenticatorSelection: a cross-platform authenticator
		// (USB security key) is the spec-aligned default but the
		// platform authenticator (TouchID) is also acceptable.
		// Empty means no constraint; the browser+OS pick.
	}
	w, err := webauthn.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("breakglass: webauthn.New: %w", err)
	}
	return w, nil
}

// User adapts identity's users.User + the credential rows owned by
// that user into the webauthn.User interface go-webauthn requires
// for Begin/Finish ceremonies. The handle is the user id encoded as
// fixed-width bytes — opaque (not displayed) and stable across
// renames, per WebAuthn §5.4.3.
type User struct {
	ID          int64
	Email       string
	DisplayName string
	Credentials []webauthn.Credential
}

// WebAuthnID returns the user handle: an 8-byte big-endian encoding
// of the database id (negative ids reinterpreted as uint64 via the
// stdlib encoding rule), padded to ensure go-webauthn never sees a
// zero-length handle (which it rejects). 8 bytes is well under the
// 64-byte spec maximum.
func (u User) WebAuthnID() []byte {
	out := make([]byte, 8)
	binary.BigEndian.PutUint64(out, uint64(u.ID)) //nolint:gosec // negative ids reinterpret deterministically
	return out
}

// WebAuthnName returns the email — operator-friendly when the
// browser displays "register a credential for <name>".
func (u User) WebAuthnName() string { return u.Email }

// WebAuthnDisplayName returns the operator-chosen display label.
// Falls back to the email when nothing is set so the registration
// dialog never shows an empty string.
func (u User) WebAuthnDisplayName() string {
	if u.DisplayName != "" {
		return u.DisplayName
	}
	return u.Email
}

// WebAuthnCredentials returns the user's stored credentials,
// already converted from the storage layer via
// CredentialStore.ToWebauthnCredentials.
func (u User) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }

// FinishRegistrationFromHTTP runs go-webauthn's FinishRegistration
// over an *http.Request, returning the new credential the caller
// must persist. Pulled into a helper so the handler stays focused on
// HTTP wiring rather than WebAuthn ceremony details. session is the
// SessionData minted by BeginRegistration; the caller is responsible
// for round-tripping it through a signature-protected cookie so the
// browser cannot tamper.
func FinishRegistrationFromHTTP(
	w *webauthn.WebAuthn, user webauthn.User,
	session webauthn.SessionData, r *http.Request,
) (*webauthn.Credential, error) {
	c, err := w.FinishRegistration(user, session, r)
	if err != nil {
		return nil, fmt.Errorf("breakglass: finish registration: %w", err)
	}
	return c, nil
}

// FinishLoginFromHTTP runs go-webauthn's FinishLogin and returns
// the matched credential plus the new sign_count the caller must
// persist via CredentialStore.RecordAssertion. session is the
// SessionData from BeginLogin.
func FinishLoginFromHTTP(
	w *webauthn.WebAuthn, user webauthn.User,
	session webauthn.SessionData, r *http.Request,
) (*webauthn.Credential, error) {
	c, err := w.FinishLogin(user, session, r)
	if err != nil {
		return nil, fmt.Errorf("breakglass: finish login: %w", err)
	}
	return c, nil
}
