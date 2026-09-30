//go:build darwin && cgo

package appbundle

/*
#cgo LDFLAGS: -framework CoreServices -framework CoreFoundation

#include <CoreServices/CoreServices.h>
#include <stdlib.h>
#include <string.h>

// edr_app_path writes the path of the first application LaunchServices knows for a bundle identifier into out and returns its
// length, or -1 when there is none or the path does not fit.
static int edr_app_path(const char *bundleID, char *out, int outLen) {
    CFStringRef bid = CFStringCreateWithCString(NULL, bundleID, kCFStringEncodingUTF8);
    if (bid == NULL) {
        return -1;
    }
    CFArrayRef urls = LSCopyApplicationURLsForBundleIdentifier(bid, NULL);
    CFRelease(bid);
    if (urls == NULL) {
        return -1;
    }
    int n = -1;
    if (CFArrayGetCount(urls) > 0) {
        CFURLRef url = (CFURLRef)CFArrayGetValueAtIndex(urls, 0);
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

// Path returns the path of the application LaunchServices has registered for bundleID, preferring the one it ranks first when
// several copies are installed, and false when none is. It works from the agent's LaunchDaemon context, verified on a VM: the system's
// LaunchServices database answers there, including for an app under a user's ~/Applications.
func Path(bundleID string) (string, bool) {
	if bundleID == "" {
		return "", false
	}
	cid := C.CString(bundleID)
	defer C.free(unsafe.Pointer(cid))
	buf := make([]byte, maxPath)
	n := C.edr_app_path(cid, (*C.char)(unsafe.Pointer(&buf[0])), C.int(len(buf)))
	if n < 0 {
		return "", false
	}
	return string(buf[:n]), true
}
