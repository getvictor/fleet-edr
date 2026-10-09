## Why

HTTP request spans were named after the raw request path, so every host id and every scanner probe created its own span name. On prod, more than 50 of the top 60 span names were probes or id-bearing paths, which buries the real routes in trace search. Separately, otelhttp recorded its own `http.server.request.duration` with no route next to the access log's routed instrument of the same name, so every request was counted twice and the request-rate panels doubled.

## What changes

- An HTTP request span ends named `METHOD /route/template` once the mux has matched a route, and `METHOD unmatched` when none matched. The span still starts named by the raw path, because the route-tier sampler decides at span start.
- Only the access log records `http.server.request.duration`, so every sample carries the route template the existing requirement already demands.

## Not changed

Sampling tiers, the sampler's inputs, and the metric's name and attributes are unchanged.
