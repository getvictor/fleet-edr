#include "_cgo_export.h"
#include "xpc_bridge.h"
#include "xpc_bridge.c"

int bridge_connect_go(const char *service_name) {
    return xpc_bridge_connect(service_name, NULL,
        (xpc_bridge_event_fn)bridgeOnEvent,
        (xpc_bridge_error_fn)bridgeOnError);
}
