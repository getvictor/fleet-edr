#include "xpc_bridge.h"

#include <xpc/xpc.h>
#include <dispatch/dispatch.h>
#include <stdlib.h>
#include <string.h>

// Per-connection state.
typedef struct {
    xpc_connection_t connection;
    dispatch_queue_t queue;
    int              in_use;
} xpc_bridge_slot;

static xpc_bridge_slot g_slots[XPC_BRIDGE_MAX_CONNECTIONS];

int xpc_bridge_connect(
    const char *service_name,
    const void *context,
    xpc_bridge_event_fn on_event,
    xpc_bridge_error_fn on_error
) {
    // Find a free slot.
    int handle = -1;
    for (int i = 0; i < XPC_BRIDGE_MAX_CONNECTIONS; i++) {
        if (!g_slots[i].in_use) {
            handle = i;
            break;
        }
    }
    if (handle < 0) {
        return -1; // All slots in use.
    }

    // Create a unique dispatch queue label per connection.
    char label[64];
    snprintf(label, sizeof(label), "com.fleetdm.edr.xpcbridge.%d", handle);

    dispatch_queue_t queue = dispatch_queue_create(label, DISPATCH_QUEUE_SERIAL);
    if (queue == NULL) {
        return -1;
    }

    xpc_connection_t conn = xpc_connection_create_mach_service(
        service_name, queue, 0 /* client, not listener */
    );
    if (conn == NULL) {
        dispatch_release(queue);
        return -1;
    }

    // Capture callback context for use in handlers.
    const void *ctx = context;
    xpc_bridge_event_fn event_cb = on_event;
    xpc_bridge_error_fn error_cb = on_error;

    xpc_connection_set_event_handler(conn, ^(xpc_object_t event) {
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

    xpc_connection_activate(conn);

    // Send a handshake message to trigger the lazy Mach port connection.
    xpc_object_t hello = xpc_dictionary_create_empty();
    xpc_dictionary_set_string(hello, "type", "hello");
    xpc_connection_send_message(conn, hello);
    xpc_release(hello);

    g_slots[handle].connection = conn;
    g_slots[handle].queue = queue;
    g_slots[handle].in_use = 1;

    return handle;
}

void xpc_bridge_disconnect(int handle) {
    if (handle < 0 || handle >= XPC_BRIDGE_MAX_CONNECTIONS) {
        return;
    }
    if (!g_slots[handle].in_use) {
        return;
    }

    if (g_slots[handle].connection != NULL) {
        xpc_connection_cancel(g_slots[handle].connection);
        g_slots[handle].connection = NULL;
    }
    if (g_slots[handle].queue != NULL) {
        dispatch_release(g_slots[handle].queue);
        g_slots[handle].queue = NULL;
    }
    g_slots[handle].in_use = 0;
}
