# Tasks

## 1. Read path

- [x] 1.1 Pass the recorded statistics through the detection-config service to the operator API.
- [x] 1.2 Gate the route with the same action as the rest of that surface, and cap the window with the deployment's retention.
- [x] 1.3 Echo the window actually served, so a caller that asked for more than retention holds is told what it is reading.
- [x] 1.4 Specify the route and its response shape in the OpenAPI document, and sync the served copy.

## 2. Surface

- [x] 2.1 Read the statistics from the client with the same validation the match-count read uses, including a floor on attempts, since the mean is a division by that number.
- [x] 2.2 Add a Cost column beside Observed: mean per attempt displayed, worst case and retry count in the cell's label.
- [x] 2.3 Keep the three states distinct, so a failed read reads as unavailable rather than as a cheap rule.
- [x] 2.4 Keep the two reads independent, so one failing does not blank the other.

## 3. Tests

- [x] 3.1 Handler: the window reaches the store, the served window is echoed, the retention cap applies to the default as well as to an explicit request, and a store failure is a 500 that does not leak the error.
- [x] 3.2 Client: every malformed envelope and row shape is rejected, each fixture malformed in exactly one way.
- [x] 3.3 Component: the unit follows the magnitude, retries are annotated only when there are some, and both unavailable states render as unavailable rather than as absence.
- [x] 3.4 Component: BOTH directions of the independence claim, since only-Cost-fails passes against a shared flag and only-Observed-fails is what catches it.
- [x] 3.5 Derive the authorization-deny table from the routes actually registered, so a route added without a row fails instead of going silently untested. That is how this route's own gate went uncovered.
