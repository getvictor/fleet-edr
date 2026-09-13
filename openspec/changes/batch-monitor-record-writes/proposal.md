# Monitor records are written per batch

Issue #1011. A monitor-mode finding was kept as a monitor record through the alert insert, one finding at a time on the detection path: one event-archive read and one MySQL transaction per record. On the lane B dev server, a single 800-event batch whose 200 findings all match a monitor-mode rule took about 5.3 seconds to drain, against 1.29 seconds with the write stubbed out. That is about 20 ms per record, all of it holding up the host's detection queue.

## What changes

- **The engine collects a batch's monitor records and writes them once**, when the batch's evaluation ends. The write happens on every exit, including a batch that ends in a retryable miss or a hard failure, because a nacked batch can be withdrawn for good once its retries run out and each record used to be written the moment it was found.
- **The store writes them together.** `InsertMonitorRecords` works in chunks of 100 records: one archive read for the union of the chunk's triggering events, then one transaction writing its rows, event links and evidence copies with multi-row inserts. Each record gets exactly what the alert insert wrote for it: the same row, dedup key, links and evidence, and no webhook delivery. A failed write fails the batch; the retry's write is a no-op for anything already committed, because of the dedup key.
- **A failed write joins the batch's own error** rather than replacing it, so a retryable miss is still classified as one.
- **Alerts keep the per-row path.** A new alert enqueues its webhook deliveries in its own transaction, and alerts are several times rarer than monitor matches, so batching them would trade durability of that pairing for little.

## Measured

The same burst on the lane B dev server: about 5.3 seconds before (5.29, 5.39) and about 1.25 seconds after (1.41, 1.21, 1.24), each run keeping 200 monitor records with 200 event links and 200 evidence copies.
