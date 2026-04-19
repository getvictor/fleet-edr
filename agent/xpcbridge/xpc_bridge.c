#include "xpc_bridge.h"

#include <dispatch/dispatch.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <xpc/xpc.h>

// Per-connection state.
typedef struct {
    xpc_connection_t connection;
    dispatch_queue_t queue;
    int in_use;
} xpc_bridge_slot;

static xpc_bridge_slot g_slots[XPC_BRIDGE_MAX_CONNECTIONS];
static pthread_mutex_t g_slots_mutex = PTHREAD_MUTEX_INITIALIZER;

int xpc_bridge_connect(const char *service_name, const void *context, xpc_bridge_event_fn on_event,
                       xpc_bridge_error_fn on_error) {
    // Find a free slot.
    pthread_mutex_lock(&g_slots_mutex);
    int handle = -1;
    for (int i = 0; i < XPC_BRIDGE_MAX_CONNECTIONS; i++) {
        if (!g_slots[i].in_use) {
            handle = i;
            g_slots[i].in_use = 1; // Reserve immediately.
            break;
        }
    }
    pthread_mutex_unlock(&g_slots_mutex);
    if (handle < 0) {
        return -1; // All slots in use.
    }

    // Create a unique dispatch queue label per connection.
    char label[64];
    snprintf(label, sizeof(label), "com.fleetdm.edr.xpcbridge.%d", handle);

    dispatch_queue_t queue = dispatch_queue_create(label, DISPATCH_QUEUE_SERIAL);
    if (queue == NULL) {
        pthread_mutex_lock(&g_slots_mutex);
        g_slots[handle].in_use = 0;
        pthread_mutex_unlock(&g_slots_mutex);
        return -1;
    }

    xpc_connection_t conn = xpc_connection_create_mach_service(service_name, queue, 0 /* client, not listener */
    );
    if (conn == NULL) {
        dispatch_release(queue);
        pthread_mutex_lock(&g_slots_mutex);
        g_slots[handle].in_use = 0;
        pthread_mutex_unlock(&g_slots_mutex);
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

    return handle;
}

int xpc_bridge_send_policy(int handle, const uint8_t *data, size_t len) {
    if (handle < 0 || handle >= XPC_BRIDGE_MAX_CONNECTIONS || data == NULL || len == 0) {
        return -1;
    }

    pthread_mutex_lock(&g_slots_mutex);
    if (!g_slots[handle].in_use) {
        pthread_mutex_unlock(&g_slots_mutex);
        return -1;
    }
    xpc_connection_t conn = g_slots[handle].connection;
    // Retain so the connection survives even if the caller tears the slot down between
    // our unlock and the async send. XPC itself refcounts the object; we mirror that.
    xpc_retain(conn);
    pthread_mutex_unlock(&g_slots_mutex);

    xpc_object_t msg = xpc_dictionary_create_empty();
    xpc_dictionary_set_string(msg, "type", "policy.update");
    xpc_dictionary_set_data(msg, "data", data, len);
    xpc_connection_send_message(conn, msg);
    xpc_release(msg);
    xpc_release(conn);
    return 0;
}

void xpc_bridge_disconnect(int handle) {
    if (handle < 0 || handle >= XPC_BRIDGE_MAX_CONNECTIONS) {
        return;
    }

    pthread_mutex_lock(&g_slots_mutex);
    if (!g_slots[handle].in_use) {
        pthread_mutex_unlock(&g_slots_mutex);
        return;
    }

    xpc_connection_t conn = g_slots[handle].connection;
    dispatch_queue_t queue = g_slots[handle].queue;
    g_slots[handle].connection = NULL;
    g_slots[handle].queue = NULL;
    g_slots[handle].in_use = 0;
    pthread_mutex_unlock(&g_slots_mutex);

    if (conn != NULL) {
        xpc_connection_cancel(conn);
        xpc_release(conn);
    }
    if (queue != NULL) {
        dispatch_release(queue);
    }
}
