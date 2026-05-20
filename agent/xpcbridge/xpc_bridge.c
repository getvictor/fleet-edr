#include "xpc_bridge.h"

#include <dispatch/dispatch.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <xpc/xpc.h>

// helloAckTimeoutNs is how long xpc_bridge_connect waits for the extension's
// "hello-ack" reply after sending "hello". Issue #178: macOS XPC sometimes
// caches a stale Mach service binding after sysextd respawns a system
// extension, leaving the agent's xpc_connection looking valid on its side
// but routing to a dead port that never reaches the extension's listener.
// xpc_connection_send_message is fire-and-forget and never surfaces this
// failure mode as an error event. The hello-ack handshake gives us positive
// confirmation of a bidirectional channel: if the extension responds, the
// connection is healthy; if not, we cancel and let the caller reconnect.
// 5s is comfortably above the ~10ms observed phantom-peer lifetime + normal
// hello round-trip latency on edr-dev (~1-3 ms), and short enough that a
// stalled agent reconnects within a single reconcile interval.
#define HELLO_ACK_TIMEOUT_NS (5LL * NSEC_PER_SEC)

// Per-connection state. hello_ack_sem is signalled once for every inbound
// "hello-ack" dictionary the extension sends; both the connect-time
// handshake and xpc_bridge_ping wait on it. The slot retains one reference;
// the connection's event handler captures the same semaphore for the lifetime
// of the connection. See xpc_bridge_disconnect for the teardown ordering.
typedef struct {
    xpc_connection_t connection;
    dispatch_queue_t queue;
    dispatch_semaphore_t hello_ack_sem;
    int in_use;
} xpc_bridge_slot;

static xpc_bridge_slot g_slots[XPC_BRIDGE_MAX_CONNECTIONS];
static pthread_mutex_t g_slots_mutex = PTHREAD_MUTEX_INITIALIZER;

// release_sem_finalizer is registered as the xpc_connection finalizer for every
// connection xpc_bridge_connect creates. The connection's event handler block
// reads the per-slot semaphore as a captured pointer; in plain C (without
// OS_OBJECT_USE_OBJC=1) Block_copy does NOT retain captured dispatch objects,
// so the block holds a non-owning copy. To guarantee the semaphore outlives
// every possible event-handler invocation, we hand the connection its own
// retained reference here and let libxpc drop it via this finalizer once the
// connection is fully torn down -- by that point the event handler can no
// longer fire, so the semaphore is safe to free. Mirrors the disconnect-side
// slot teardown but is decoupled from it so a late hello-ack arriving after
// xpc_bridge_disconnect cannot UAF the semaphore.
static void release_sem_finalizer(void *ctx) {
    dispatch_semaphore_t sem = (dispatch_semaphore_t)ctx;
    if (sem != NULL) {
        dispatch_release(sem);
    }
}

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

    // hello-ack synchronisation (issue #178). The block below signals this
    // semaphore on every inbound hello-ack message; xpc_bridge_connect waits
    // on it once after sending the initial hello, and xpc_bridge_ping waits
    // on it again for each subsequent heartbeat. A stale Mach port binding or
    // a mid-session channel break therefore surfaces as a wait timeout rather
    // than as a silent one-way channel.
    //
    // Ownership: three logical references to this object exist at steady
    // state -- the local stack variable here, the slot's ref (assigned at
    // success below), and the connection's finalizer ref (set just below).
    // The block captures the pointer but in plain C does NOT retain it, so
    // we hand the connection an explicit retained ref via
    // xpc_connection_set_finalizer_f. That ref is dropped only after libxpc
    // has fully torn the connection down (and therefore can no longer invoke
    // the event handler), which makes a late hello-ack race with
    // dispatch_release impossible on either the connect-timeout or
    // disconnect cleanup paths.
    dispatch_semaphore_t hello_ack_sem = dispatch_semaphore_create(0);
    if (hello_ack_sem == NULL) {
        xpc_release(conn);
        dispatch_release(queue);
        pthread_mutex_lock(&g_slots_mutex);
        g_slots[handle].in_use = 0;
        pthread_mutex_unlock(&g_slots_mutex);
        return -1;
    }
    // Retain once for the finalizer ownership, then register it. The retain
    // must precede set_finalizer_f -- if libxpc tears the connection down
    // between create and set_finalizer_f (it won't on the create path, but
    // belt-and-braces), the finalizer would otherwise drop a ref we hadn't
    // taken yet.
    dispatch_retain(hello_ack_sem);
    xpc_connection_set_context(conn, hello_ack_sem);
    xpc_connection_set_finalizer_f(conn, release_sem_finalizer);

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
          // Hello-ack short-circuit: the extension replies to every "hello"
          // with a "type":"hello-ack" message (initial handshake and every
          // heartbeat). Signal the slot's semaphore so the matching waiter
          // (connect or ping) wakes up. The cost is one strcmp per inbound
          // dictionary, negligible against the JSON decode that follows.
          const char *msg_type = xpc_dictionary_get_string(event, "type");
          if (msg_type != NULL && strcmp(msg_type, "hello-ack") == 0) {
              dispatch_semaphore_signal(hello_ack_sem);
              return;
          }
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

    // Wait for the extension's hello-ack. If it doesn't arrive within the
    // timeout the bidirectional channel is broken (issue #178): cancel and
    // return failure so the caller's reconnect loop retries against a fresh
    // Mach port binding.
    dispatch_time_t deadline = dispatch_time(DISPATCH_TIME_NOW, HELLO_ACK_TIMEOUT_NS);
    if (dispatch_semaphore_wait(hello_ack_sem, deadline) != 0) {
        // Cancel + release drop our refcounts so a reconnect loop hitting
        // repeated timeouts (stale Mach binding, extension wedged) does not
        // leak one xpc_connection_t + one dispatch_queue_t + one semaphore
        // per attempt. The release_sem_finalizer registered above holds the
        // OTHER semaphore reference, so even if libxpc has a late hello-ack
        // queued at the moment we call dispatch_release here, the semaphore
        // stays alive until the connection finishes cancellation -- at which
        // point the event handler can no longer fire.
        xpc_connection_cancel(conn);
        xpc_release(conn);
        dispatch_release(queue);
        dispatch_release(hello_ack_sem);
        pthread_mutex_lock(&g_slots_mutex);
        g_slots[handle].in_use = 0;
        pthread_mutex_unlock(&g_slots_mutex);
        return -1;
    }

    // Publish the conn + queue + semaphore under the slots mutex so a
    // concurrent xpc_bridge_send_application_control or xpc_bridge_ping
    // cannot observe (in_use=1, connection=NULL). The earlier reservation
    // marked in_use=1 outside this critical section for liveness; this
    // second critical section commits the actual handles atomically with
    // respect to send/ping/disconnect.
    pthread_mutex_lock(&g_slots_mutex);
    g_slots[handle].connection = conn;
    g_slots[handle].queue = queue;
    g_slots[handle].hello_ack_sem = hello_ack_sem;
    pthread_mutex_unlock(&g_slots_mutex);

    return handle;
}

int xpc_bridge_send_application_control(int handle, const uint8_t *data, size_t len) {
    if (handle < 0 || handle >= XPC_BRIDGE_MAX_CONNECTIONS || data == NULL || len == 0) {
        return -1;
    }

    pthread_mutex_lock(&g_slots_mutex);
    if (!g_slots[handle].in_use) {
        pthread_mutex_unlock(&g_slots_mutex);
        return -1;
    }
    xpc_connection_t conn = g_slots[handle].connection;
    if (conn == NULL) {
        // Slot is reserved (in_use=1) but xpc_bridge_connect has not yet
        // committed the connection handle. Treat as "not yet ready" and let
        // the caller retry on the next poll cycle.
        pthread_mutex_unlock(&g_slots_mutex);
        return -1;
    }
    // Retain so the connection survives even if the caller tears the slot down between
    // our unlock and the async send. XPC itself refcounts the object; we mirror that.
    xpc_retain(conn);
    pthread_mutex_unlock(&g_slots_mutex);

    xpc_object_t msg = xpc_dictionary_create_empty();
    xpc_dictionary_set_string(msg, "type", "application_control.update");
    xpc_dictionary_set_data(msg, "data", data, len);
    xpc_connection_send_message(conn, msg);
    xpc_release(msg);
    xpc_release(conn);
    return 0;
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
int xpc_bridge_ping(int handle, uint64_t timeout_ns) {
    if (handle < 0 || handle >= XPC_BRIDGE_MAX_CONNECTIONS) {
        return -1;
    }

    // Snapshot the slot's connection + semaphore under the mutex and retain
    // both so a concurrent disconnect cannot free them out from under us
    // while we are waiting. Pairing release happens at the end of this
    // function regardless of success or timeout.
    pthread_mutex_lock(&g_slots_mutex);
    if (!g_slots[handle].in_use) {
        pthread_mutex_unlock(&g_slots_mutex);
        return -1;
    }
    xpc_connection_t conn = g_slots[handle].connection;
    dispatch_semaphore_t sem = g_slots[handle].hello_ack_sem;
    if (conn == NULL || sem == NULL) {
        pthread_mutex_unlock(&g_slots_mutex);
        return -1;
    }
    xpc_retain(conn);
    dispatch_retain(sem);
    pthread_mutex_unlock(&g_slots_mutex);

    // Drain any pending signals so the semaphore count starts at zero. The
    // initial connect handshake consumes the first signal already, but a
    // prior ping with a slow ack could leave a stale signal that would let
    // the next wait return immediately without the extension actually being
    // alive (e.g. ack arrived after our previous timeout fired).
    while (dispatch_semaphore_wait(sem, DISPATCH_TIME_NOW) == 0) {
    }

    xpc_object_t hello = xpc_dictionary_create_empty();
    xpc_dictionary_set_string(hello, "type", "hello");
    xpc_connection_send_message(conn, hello);
    xpc_release(hello);

    dispatch_time_t deadline = dispatch_time(DISPATCH_TIME_NOW, (int64_t)timeout_ns);
    int result = (dispatch_semaphore_wait(sem, deadline) == 0) ? 0 : -1;

    xpc_release(conn);
    dispatch_release(sem);
    return result;
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
    dispatch_semaphore_t sem = g_slots[handle].hello_ack_sem;
    g_slots[handle].connection = NULL;
    g_slots[handle].queue = NULL;
    g_slots[handle].hello_ack_sem = NULL;
    g_slots[handle].in_use = 0;
    pthread_mutex_unlock(&g_slots_mutex);

    if (conn != NULL) {
        xpc_connection_cancel(conn);
        xpc_release(conn);
    }
    if (queue != NULL) {
        dispatch_release(queue);
    }
    if (sem != NULL) {
        // Drop the slot's reference to the semaphore. The release_sem_finalizer
        // registered on the connection at connect time holds the other reference
        // and will be invoked by libxpc only after the connection is fully torn
        // down -- so a late hello-ack arriving between xpc_connection_cancel and
        // the finalizer cannot UAF the semaphore. Concurrent pings already
        // observed in_use=0 above and bailed out before touching the slot.
        dispatch_release(sem);
    }
}
