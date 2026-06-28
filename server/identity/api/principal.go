package api

import (
	"strconv"
	"strings"
)

// PrincipalType discriminates the kind of actor a PrincipalRef identifies. It is the authoritative, indexable discriminator stored on
// the principals row; the same value is also encoded in the principal id's prefix so a bare id is self-describing on the wire and in the
// database. The two never disagree because a single mint helper sets both. See ADR-0017.
type PrincipalType string

const (
	// PrincipalUser is a human operator (a users row).
	PrincipalUser PrincipalType = "user"
	// PrincipalServiceAccount is a non-human API principal (a service_accounts row, ADR-0013).
	PrincipalServiceAccount PrincipalType = "service_account"
	// PrincipalSystem is the deployment itself: env-seed writes, background jobs, and migrations attribute to it rather than to a
	// human or to a free-form literal. It is a singleton.
	PrincipalSystem PrincipalType = "system"
)

// Principal id prefixes. The local part after the prefix is the owning subtype row's autoincrement key (usr_<users.id> /
// svc_<service_accounts.id>), which is stable and never reused: a removed subtype row leaves a tombstoned principals row behind and the
// autoincrement key is never reissued. Only UserID below parses the local part; everything else treats the id as opaque.
const (
	principalUserPrefix           = "usr_"
	principalServiceAccountPrefix = "svc_"
	// PrincipalSystemID is the id of the singleton system principal. Type is PrincipalSystem; it carries no numeric local part.
	PrincipalSystemID = "sys"
	// systemLabel is the display label of the system principal.
	systemLabel = "system"
)

// PrincipalRef is the portable identity of an authenticated actor. ID is the type-prefixed principal id; Type is the discriminator;
// Label is the display name (a user's email, a service account's name, or "system"). It is carried on Actor so the acting principal
// survives authentication for every actor kind, and it is the single value recorded for audit and per-row attribution. See ADR-0017.
type PrincipalRef struct {
	ID    string        `json:"id"`
	Type  PrincipalType `json:"type"`
	Label string        `json:"label"`
}

// UserPrincipalID returns the principal id for a numeric users.id.
func UserPrincipalID(userID int64) string {
	return principalUserPrefix + strconv.FormatInt(userID, 10)
}

// ServiceAccountPrincipalID returns the principal id for a numeric service_accounts.id.
func ServiceAccountPrincipalID(serviceAccountID int64) string {
	return principalServiceAccountPrefix + strconv.FormatInt(serviceAccountID, 10)
}

// SystemPrincipal returns the singleton system principal ref, used to attribute env-seed and background writes.
func SystemPrincipal() PrincipalRef {
	return PrincipalRef{ID: PrincipalSystemID, Type: PrincipalSystem, Label: systemLabel}
}

// UserPrincipal builds the ref for a human operator from the user's id and display label (email).
func UserPrincipal(userID int64, label string) PrincipalRef {
	return PrincipalRef{ID: UserPrincipalID(userID), Type: PrincipalUser, Label: label}
}

// ServiceAccountPrincipal builds the ref for a service account from its numeric id and display name.
func ServiceAccountPrincipal(serviceAccountID int64, label string) PrincipalRef {
	return PrincipalRef{ID: ServiceAccountPrincipalID(serviceAccountID), Type: PrincipalServiceAccount, Label: label}
}

// UserID returns the numeric users.id when this principal is a user, parsing it back out of the usr_<n> id. Only the user-on-user paths
// (self-edit, creator checks) call it; everything else identifies the actor by ID. It returns ok=false for any non-user id (svc_/sys),
// a malformed local part, or a non-positive value, so callers cannot accidentally treat a service account as a user. It keys off the id
// prefix rather than Type so it still works on a ref reconstructed from a bare attribution string with Type unset.
func (p PrincipalRef) UserID() (int64, bool) {
	rest, ok := strings.CutPrefix(p.ID, principalUserPrefix)
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseInt(rest, 10, 64)
	if err != nil || n <= 0 {
		return 0, false
	}
	return n, true
}

// PrincipalTypeForID reports the principal type encoded in a bare id's prefix. It is the read-side inverse of the mint helpers: code
// that loads an attribution-column string uses it to recover the type without a database lookup. ok is false for an id carrying no
// recognized prefix (a malformed or legacy value).
func PrincipalTypeForID(id string) (PrincipalType, bool) {
	switch {
	case id == PrincipalSystemID:
		return PrincipalSystem, true
	case strings.HasPrefix(id, principalUserPrefix):
		return PrincipalUser, true
	case strings.HasPrefix(id, principalServiceAccountPrefix):
		return PrincipalServiceAccount, true
	default:
		return "", false
	}
}
