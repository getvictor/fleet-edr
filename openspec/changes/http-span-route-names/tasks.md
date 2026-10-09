## 1. Server

- [x] 1.1 The span-name formatter returns the route template once `r.Pattern` is set; the access log renames an unmatched request's span to `METHOD unmatched`
- [x] 1.2 otelhttp records no metrics of its own (noop meter provider)
- [x] 1.3 Tests: the span name for a matched and an unmatched request, and no route-less duration metric from otelhttp
