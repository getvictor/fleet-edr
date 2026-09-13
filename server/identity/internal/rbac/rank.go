package rbac

const (
	roleSuperAdmin   = "super_admin"
	userStatusActive = "active"
)

// roleRank orders the seeded roles by privilege. Higher wins.
//
//nolint:mnd // ordinal ranks of the seeded roles, not magic constants
var roleRank = map[string]int{roleSuperAdmin: 5, "admin": 4, "senior_analyst": 3, "analyst": 2, "auditor": 1}

// GrantableRoles is every seeded role below super_admin: the roles an admin grants a user in the Users page, and the roles an SSO
// group mapping may grant. super_admin is granted only by a super_admin, and never from an IdP group.
var GrantableRoles = map[string]bool{"analyst": true, "senior_analyst": true, "auditor": true, "admin": true}

// MostPrivileged returns the highest-ranked role in roles, or "" for none. It is how one role is chosen where several apply: the
// single role the Users list shows for a user holding more than one global binding (legacy hand-written SQL), and the role an SSO
// sign-in maps from several IdP groups. A role outside the seeded set ranks below every seeded one.
func MostPrivileged(roles []string) string {
	best, bestRank := "", -1
	for _, r := range roles {
		if roleRank[r] > bestRank {
			best, bestRank = r, roleRank[r]
		}
	}
	return best
}
