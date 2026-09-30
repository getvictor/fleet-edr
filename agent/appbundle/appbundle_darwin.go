//go:build darwin && cgo

package appbundle

/*
#cgo LDFLAGS: -framework CoreServices -framework CoreFoundation

#include <CoreServices/CoreServices.h>
#include <stdlib.h>
#include <string.h>

// edr_app_count returns how many applications LaunchServices has registered for a bundle identifier, and edr_app_path writes the
// path of the one at index into out, returning its length or -1. They are two calls so Go owns every buffer.
static CFArrayRef edr_app_urls(const char *bundleID) {
    CFStringRef bid = CFStringCreateWithCString(NULL, bundleID, kCFStringEncodingUTF8);
    if (bid == NULL) {
        return NULL;
    }
    CFArrayRef urls = LSCopyApplicationURLsForBundleIdentifier(bid, NULL);
    CFRelease(bid);
    return urls;
}

static int edr_app_count(const char *bundleID) {
    CFArrayRef urls = edr_app_urls(bundleID);
    if (urls == NULL) {
        return 0;
    }
    int n = (int)CFArrayGetCount(urls);
    CFRelease(urls);
    return n;
}

static int edr_app_path(const char *bundleID, int index, char *out, int outLen) {
    CFArrayRef urls = edr_app_urls(bundleID);
    if (urls == NULL) {
        return -1;
    }
    int n = -1;
    if (index < CFArrayGetCount(urls)) {
        CFURLRef url = (CFURLRef)CFArrayGetValueAtIndex(urls, index);
        if (CFURLGetFileSystemRepresentation(url, true, (UInt8 *)out, outLen)) {
            n = (int)strlen(out);
        }
    }
    CFRelease(urls);
    return n;
}
*/
import "C"

import "unsafe"

// maxPath is PATH_MAX, the longest path CFURLGetFileSystemRepresentation can hand back with its terminating NUL; a longer one is refused.
const maxPath = 1024

// Paths returns every application LaunchServices has registered for bundleID, or none. It works from the agent's LaunchDaemon
// context, verified on a VM: the system's LaunchServices database answers there, including for apps under a user's ~/Applications.
// All of them, not the first: two copies can share an identifier, and which one a TCC record is about is not something the order
// says.
func Paths(bundleID string) []string {
	if bundleID == "" {
		return nil
	}
	cid := C.CString(bundleID)
	defer C.free(unsafe.Pointer(cid))
	var out []string
	for i := range int(C.edr_app_count(cid)) {
		buf := make([]byte, maxPath)
		if n := C.edr_app_path(cid, C.int(i), (*C.char)(unsafe.Pointer(&buf[0])), C.int(len(buf))); n >= 0 {
			out = append(out, string(buf[:n]))
		}
	}
	return out
}
