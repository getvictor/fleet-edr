package breakglass

import (
	"errors"
	"unicode/utf8"
)

// MinPasswordRunes is the wave-1 break-glass password length floor.
// CIS Password Policy Guide v1.2 specifies 8+ characters for
// MFA-protected accounts; OWASP ASVS 4.0.3 §2.1.1 specifies ≥ 12.
// Mandatory WebAuthn places this account in the "with MFA" bucket;
// 12 sits comfortably above the CIS floor and matches OWASP.
//
// No zxcvbn entropy gate in wave 1: WebAuthn carries the cryptographic
// factor and the password is the shoulder-surf defense gate.
const MinPasswordRunes = 12

// ErrPasswordTooShort signals a redemption attempt with a password below MinPasswordRunes runes. Caller surfaces a directed reason
// (`password.too_short`) without leaking the configured floor in the response body.
var ErrPasswordTooShort = errors.New("breakglass: password too short")

// ValidatePassword enforces the wave-1 length-only break-glass
// password policy. Rune-counted (utf8) so a password of 12 emoji
// counts as 12, not as 48 bytes — preventing an operator from
// hitting the floor with a single multi-byte sequence.
//
// Returns ErrPasswordTooShort when len([]rune(password)) <
// MinPasswordRunes; nil otherwise. The caller composes the error
// into the redemption response.
func ValidatePassword(password string) error {
	if utf8.RuneCountInString(password) < MinPasswordRunes {
		return ErrPasswordTooShort
	}
	return nil
}
