// Build constraint must match the sibling Go files (receiver.go, callbacks.go) so this C source is excluded under
// linux + cgo=1 and darwin + cgo=0 alike. Without it, a `go build` under cgo finds bridge.c with no companion Go
// file `import "C"`-ing on the matching platform and errors with "C source files not allowed when not using cgo
// or SWIG". Plain `//go:build` directives are honoured by go/build for .c sources in cgo packages.
//
//go:build darwin && cgo

#include "_cgo_export.h"
#include "xpc_bridge.c"
#include "xpc_bridge.h"

int bridge_connect_go(const char *service_name, int receiver_id) {
    // Pass receiver_id as the context pointer so callbacks can route to the correct Go receiver.
    return xpc_bridge_connect(service_name, (const void *)(intptr_t)receiver_id, (xpc_bridge_event_fn)bridgeOnEvent,
                              (xpc_bridge_error_fn)bridgeOnError);
}
