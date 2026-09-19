package api

import (
	"errors"
	"time"
)

// ReachableAddress is one destination a contained host may still reach (issue #1059).
//
// A responder contains a host and then needs it to stay reachable by a few trusted systems: an MDM or remediation server, a forensic
// collection share, a VPN concentrator. Without this, containment is all or nothing and the responder's own tooling is cut off with
// the intruder's.
type ReachableAddress struct {
	// CIDR is the destination range, stored masked and canonical. A bare address is stored as its single-address prefix, so
	// "192.0.2.7" reads back as "192.0.2.7/32" and one destination has one spelling.
	CIDR string `json:"cidr"`
	// Port is the single destination port this entry allows, or 0 for every port. A range is not offered: the systems a responder
	// keeps reachable are named services, and a range is the shape that turns an allowance into a hole nobody reviews.
	//
	// 0 carries the "every port" meaning rather than naming a destination, and an omitted port is indistinguishable from an
	// explicit 0. That collapse is safe rather than merely convenient: port 0 is reserved and nothing is reachable on it, so there
	// is no entry an operator can write that this loses. Tracking presence separately would buy the ability to refuse an input that
	// names a port nothing can listen on.
	Port int `json:"port,omitempty"`
	// Transport is "tcp", "udp", or "" for both. An entry written without one allows both, which is what an operator naming an
	// address and no protocol means.
	Transport string `json:"transport,omitempty"`
	// Note is what the operator called it, carried so the console and the audit trail say "MDM server" rather than an address.
	Note string `json:"note,omitempty"`
}

// Transport values a ReachableAddress may carry.
const (
	TransportTCP = "tcp"
	TransportUDP = "udp"
)

// ReachableSet is the deployment's whole reachable-address set at one version.
//
// Versioned as a whole rather than per entry, because it is delivered as a whole: a host holds one version, and a version names
// exactly one list. Per-entry versions would let a host hold half a set, which is a state no reader could describe.
type ReachableSet struct {
	Version   int64              `json:"version"`
	Addresses []ReachableAddress `json:"addresses"`
	UpdatedAt *time.Time         `json:"updated_at,omitempty"`
	UpdatedBy string             `json:"updated_by,omitempty"`
}

// MaxReachableAddresses caps the set. The list rides every contained host's command payload and becomes one filter rule per entry on
// the host, so it is bounded; 64 is far past the handful of systems the issue describes and well short of anything that would bloat a
// command or a rule table.
const MaxReachableAddresses = 64

// MaxReachableNoteLength caps an entry's note in runes.
const MaxReachableNoteLength = 200

// Minimum prefix bits an entry may carry, per family.
//
// This is what stops an allowance from quietly becoming "no containment". Refusing only 0.0.0.0/0 and ::/0 would be theatre, since
// 0.0.0.0/1 and 128.0.0.0/1 together are the same thing written twice. The floors are set where a legitimate operator range still
// fits: 10.0.0.0/8 is the largest private IPv4 block anyone actually runs, and /32 is the smallest IPv6 allocation a site is given,
// so neither floor refuses a range an operator would reasonably write.
//
// The floor bounds coverage rather than eliminating it: MaxReachableAddresses entries at the floor reach a quarter of IPv4 at worst.
// That is a deliberate stopping point. Refusing SETS whose union is too broad would mean interval arithmetic over two address
// families for an operator who can already be trusted with the reason field and the audit trail, and the console showing what a set
// covers is the honest answer to a set that is too wide, not a solver.
const (
	MinReachablePrefixBitsV4 = 8
	MinReachablePrefixBitsV6 = 32
)

// MaxReachableReasonLength caps the reason recorded with a change, matching the containment change's own cap.
const MaxReachableReasonLength = MaxContainmentReasonLength

// Errors a reachable-set replacement can fail with. Each is a distinct operator-visible refusal, so the API can say which entry was
// wrong and why rather than answering "invalid".
var (
	// ErrReachableReasonRequired is a replacement with no reason. The set widens what every contained host can talk to, so a change
	// to it is audited the way a containment is.
	ErrReachableReasonRequired = errors.New("reachable set: reason is required")
	// ErrReachableReasonTooLong is a reason over MaxReachableReasonLength runes.
	ErrReachableReasonTooLong = errors.New("reachable set: reason is too long")
	// ErrReachableTooMany is a set over MaxReachableAddresses entries.
	ErrReachableTooMany = errors.New("reachable set: too many addresses")
	// ErrReachableInvalidCIDR is an entry whose address is not an address or a CIDR range.
	ErrReachableInvalidCIDR = errors.New("reachable set: address is not an IP address or CIDR range")
	// ErrReachableTooBroad is an entry whose range is broader than the family's floor, which would leave containment meaningless.
	ErrReachableTooBroad = errors.New("reachable set: address range is too broad")
	// ErrReachableInvalidPort is a port outside 0..65535.
	ErrReachableInvalidPort = errors.New("reachable set: port is out of range")
	// ErrReachableInvalidTransport is a transport other than tcp, udp, or unset.
	ErrReachableInvalidTransport = errors.New("reachable set: transport must be tcp or udp")
	// ErrReachableNoteTooLong is a note over MaxReachableNoteLength runes.
	ErrReachableNoteTooLong = errors.New("reachable set: note is too long")
	// ErrReachableDuplicate is the same destination, port and transport written twice. Refused rather than collapsed, because two
	// entries with different notes are two claims about one rule and silently keeping one of them hides the other operator's.
	ErrReachableDuplicate = errors.New("reachable set: the same destination is listed twice")
	// ErrReachableVersionConflict is a conditional replacement of a set that changed since the caller read it.
	ErrReachableVersionConflict = errors.New("reachable set: it was changed since it was read")
)
