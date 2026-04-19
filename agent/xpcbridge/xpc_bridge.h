#ifndef XPC_BRIDGE_H
#define XPC_BRIDGE_H

#include <stddef.h>
#include <stdint.h>

// Callback invoked when an event message arrives.
// data is the raw JSON bytes, len is the byte count.
// data is only valid for the duration of the callback.
typedef void (*xpc_bridge_event_fn)(const void *context, const uint8_t *data, size_t len);

// Callback invoked on connection error/interruption.
typedef void (*xpc_bridge_error_fn)(const void *context, int error_code);

// Error codes passed to the error callback.
#define XPC_BRIDGE_ERROR_CONNECTION_INVALID 1
#define XPC_BRIDGE_ERROR_CONNECTION_INTERRUPTED 2
#define XPC_BRIDGE_ERROR_TERMINATED 3

// Maximum number of simultaneous XPC connections.
#define XPC_BRIDGE_MAX_CONNECTIONS 4

// Connect to a named XPC Mach service as a client.
// Returns a non-negative connection handle on success, -1 on failure.
int xpc_bridge_connect(const char *service_name, const void *context, xpc_bridge_event_fn on_event,
                       xpc_bridge_error_fn on_error);

// Disconnect and clean up a specific connection.
void xpc_bridge_disconnect(int handle);

// Send a "policy.update" message to the peer on the given handle. The payload is copied
// into an XPC dictionary under the "data" key alongside "type"="policy.update". Returns
// 0 on success, -1 if the handle is invalid or the connection is gone. XPC send is
// asynchronous — success here means the message was enqueued on the connection, not that
// the peer received it.
int xpc_bridge_send_policy(int handle, const uint8_t *data, size_t len);

#endif
