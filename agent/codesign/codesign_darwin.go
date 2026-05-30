//go:build darwin && cgo

package codesign

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdlib.h>
#include <string.h>

// edr_signing_t is the C-side result of edr_evaluate_signing. team_id /
// signing_id are NUL-terminated UTF-8 (empty for an unsigned binary).
// is_platform is 1 when the binary validates against "anchor apple". ok is 1
// only when a SecStaticCode could be created for the path (the file exists and
// is readable); ok=0 means absent / unreadable, which the caller maps to
// (nil, false) so the rule treats it as "cannot classify" and skips.
typedef struct {
    char team_id[128];
    char signing_id[256];
    int  is_platform;
    int  ok;
} edr_signing_t;

static void edr_copy_cfstring(CFStringRef s, char *buf, size_t buflen) {
    buf[0] = '\0';
    if (s == NULL) {
        return;
    }
    // On failure (e.g. the buffer cannot hold the string + its NUL) CFStringGetCString leaves buf's contents undefined,
    // so a later C.GoString could read past the data. Re-NUL the buffer on failure to keep it a valid empty C string.
    if (!CFStringGetCString(s, buf, (CFIndex)buflen, kCFStringEncodingUTF8)) {
        buf[0] = '\0';
    }
}

static edr_signing_t edr_evaluate_signing(const char *path) {
    edr_signing_t out;
    memset(&out, 0, sizeof(out));

    CFURLRef url = CFURLCreateFromFileSystemRepresentation(NULL, (const UInt8 *)path, (CFIndex)strlen(path), false);
    if (url == NULL) {
        return out; // ok stays 0
    }

    SecStaticCodeRef code = NULL;
    OSStatus st = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code);
    CFRelease(url);
    if (st != errSecSuccess || code == NULL) {
        if (code != NULL) {
            CFRelease(code);
        }
        return out; // absent / unreadable -> ok stays 0
    }
    out.ok = 1;

    CFDictionaryRef info = NULL;
    if (SecCodeCopySigningInformation(code, kSecCSSigningInformation, &info) == errSecSuccess && info != NULL) {
        edr_copy_cfstring((CFStringRef)CFDictionaryGetValue(info, kSecCodeInfoTeamIdentifier), out.team_id, sizeof(out.team_id));
        edr_copy_cfstring((CFStringRef)CFDictionaryGetValue(info, kSecCodeInfoIdentifier), out.signing_id, sizeof(out.signing_id));
        CFRelease(info);
    }

    // "anchor apple" is the network-free Apple-platform-binary check. kSecCSNoNetworkAccess restricts validation to LOCAL checks:
    // an Endpoint Security callback must never block on an OCSP/CRL fetch, and even off that thread we keep the agent's enqueue
    // path free of network I/O. "anchor apple" is satisfiable entirely from the on-disk chain, so local-only is sufficient.
    SecRequirementRef req = NULL;
    if (SecRequirementCreateWithString(CFSTR("anchor apple"), kSecCSDefaultFlags, &req) == errSecSuccess && req != NULL) {
        if (SecStaticCodeCheckValidity(code, kSecCSNoNetworkAccess, req) == errSecSuccess) {
            out.is_platform = 1;
        }
        CFRelease(req);
    }

    CFRelease(code);
    return out;
}
*/
import "C"

import "unsafe"

// Evaluate reads the on-disk code signing of the binary (or bundle) at path
// via SecStaticCode, network-free. It returns (nil, false) when the path is
// empty or SecStaticCode cannot open the file (absent / unreadable): the
// server rule treats a missing executable_code_signing as "cannot classify"
// and skips, staying high-precision. A present-but-unsigned binary returns a
// Result with empty TeamID / SigningID and IsPlatformBinary=false — the prime
// attacker case (an ad-hoc / unsigned dropper) the rule fires on.
//
// Mirrors the proven SecCode form in the extension's SigningInfoFallback.swift
// and the (now removed) evaluateExecutableSigning, but runs in the agent so a
// SIP-enabled host's extension sandbox cannot block the read.
func Evaluate(path string) (*Result, bool) {
	if path == "" {
		return nil, false
	}
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))

	res := C.edr_evaluate_signing(cpath)
	if res.ok == 0 {
		return nil, false
	}
	return &Result{
		TeamID:    C.GoString(&res.team_id[0]),
		SigningID: C.GoString(&res.signing_id[0]),
		// SecCodeCopySigningInformation's static read does not carry the live process codesigning_flags, and the rule does
		// not consume flags (it gates on team_id + is_platform_binary). Kept at 0 to satisfy the wire schema's required field.
		Flags:            0,
		IsPlatformBinary: res.is_platform != 0,
	}, true
}
