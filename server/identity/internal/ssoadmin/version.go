package ssoadmin

import (
	"fmt"
	"strconv"
	"strings"
)

// Version is what a client reads and sends back to say which configuration it was editing.
//
// The SSO settings surface spans two stored parts, versioned separately: the OIDC configuration (`oidc_config.config_version`) and
// the deployment settings the external URL lives in (`app_config.version`). Checking one leaves the other open, so a save that named
// only the OIDC version would still overwrite an external URL somebody changed in the meantime (issue #1046). One value covering
// both is what makes "the configuration I was editing" a thing a client can name at all.
//
// Zero on either part means that part did not exist yet, which is a state a client can legitimately have read: an unconfigured
// deployment. It is not a missing version.
type Version struct {
	OIDC int64
	App  int64
}

// String is the wire form. Clients MUST treat it as opaque and send back exactly what they read: the two numbers are an
// implementation detail of which tables happen to store the configuration today, and a client that takes them apart would break
// when that changes.
func (v Version) String() string {
	return strconv.FormatInt(v.OIDC, 10) + "." + strconv.FormatInt(v.App, 10)
}

// ParseVersion reads the wire form back. It is deliberately strict: a version the server did not issue cannot be honoured as a
// concurrency check, and treating it as "no version" would turn a client's conditional save into an unconditional one, which is the
// overwrite the check exists to prevent.
func ParseVersion(s string) (Version, error) {
	oidc, app, ok := strings.Cut(s, ".")
	if !ok {
		return Version{}, fmt.Errorf("ssoadmin: version %q is not two parts", s)
	}
	oidcVersion, err := strconv.ParseInt(oidc, 10, 64)
	if err != nil || oidcVersion < 0 {
		return Version{}, fmt.Errorf("ssoadmin: version %q has an unreadable first part", s)
	}
	appVersion, err := strconv.ParseInt(app, 10, 64)
	if err != nil || appVersion < 0 {
		return Version{}, fmt.Errorf("ssoadmin: version %q has an unreadable second part", s)
	}
	return Version{OIDC: oidcVersion, App: appVersion}, nil
}
