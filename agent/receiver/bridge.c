#include "_cgo_export.h"
#include "xpc_bridge.c"
#include "xpc_bridge.h"

int bridge_connect_go(const char *service_name, int receiver_id) {
    // Pass receiver_id as the context pointer so callbacks can route to the correct Go receiver.
    return xpc_bridge_connect(service_name, (const void *)(intptr_t)receiver_id, (xpc_bridge_event_fn)bridgeOnEvent,
                              (xpc_bridge_error_fn)bridgeOnError);
}
