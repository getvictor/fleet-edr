#include "xpc_bridge.h"

#include <xpc/xpc.h>
#include <dispatch/dispatch.h>
#include <stdlib.h>
#include <string.h>

// Internal state for the XPC connection.
static xpc_connection_t g_connection = NULL;
static dispatch_queue_t g_queue = NULL;

int xpc_bridge_connect(
    const char *service_name,
    const void *context,
    xpc_bridge_event_fn on_event,
    xpc_bridge_error_fn on_error
) {
    if (g_connection != NULL) {
        return -1; // Already connected.
    }

    g_queue = dispatch_queue_create("com.fleetdm.edr.xpcbridge", DISPATCH_QUEUE_SERIAL);
    if (g_queue == NULL) {
        return -1;
    }

    g_connection = xpc_connection_create_mach_service(
        service_name, g_queue, 0 /* client, not listener */
    );
    if (g_connection == NULL) {
        g_queue = NULL;
        return -1;
    }

    // Capture callback context for use in handlers. The context pointer must
    // remain valid for the lifetime of the connection.
    const void *ctx = context;
    xpc_bridge_event_fn event_cb = on_event;
    xpc_bridge_error_fn error_cb = on_error;

    xpc_connection_set_event_handler(g_connection, ^(xpc_object_t event) {
        xpc_type_t type = xpc_get_type(event);

        if (type == XPC_TYPE_ERROR) {
            if (event == XPC_ERROR_CONNECTION_INVALID) {
                if (error_cb) {
                    error_cb(ctx, XPC_BRIDGE_ERROR_CONNECTION_INVALID);
                }
            } else if (event == XPC_ERROR_CONNECTION_INTERRUPTED) {
                if (error_cb) {
                    error_cb(ctx, XPC_BRIDGE_ERROR_CONNECTION_INTERRUPTED);
                }
            } else if (event == XPC_ERROR_TERMINATION_IMMINENT) {
                if (error_cb) {
                    error_cb(ctx, XPC_BRIDGE_ERROR_TERMINATED);
                }
            }
            return;
        }

        if (type == XPC_TYPE_DICTIONARY) {
            // The extension sends events as a dictionary with a "data" key
            // containing raw JSON bytes.
            size_t data_len = 0;
            const void *data = xpc_dictionary_get_data(event, "data", &data_len);
            if (data != NULL && data_len > 0 && event_cb) {
                // Copy the data before invoking the callback so the caller
                // does not depend on XPC message lifetime.
                uint8_t *buf = malloc(data_len);
                if (buf != NULL) {
                    memcpy(buf, data, data_len);
                    event_cb(ctx, buf, data_len);
                    free(buf);
                }
            }
        }
    });

    xpc_connection_activate(g_connection);

    // Send a handshake message to trigger the lazy Mach port connection.
    // Without this, the listener never sees the peer because XPC client
    // connections only bootstrap on the first send.
    xpc_object_t hello = xpc_dictionary_create_empty();
    xpc_dictionary_set_string(hello, "type", "hello");
    xpc_connection_send_message(g_connection, hello);

    return 0;
}

void xpc_bridge_disconnect(void) {
    if (g_connection != NULL) {
        xpc_connection_cancel(g_connection);
        g_connection = NULL;
    }
    // dispatch_release is not needed for queues created with
    // dispatch_queue_create under ARC-compatible C code on modern macOS;
    // setting to NULL is sufficient for our purposes.
    g_queue = NULL;
}
