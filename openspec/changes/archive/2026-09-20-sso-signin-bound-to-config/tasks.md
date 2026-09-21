# Tasks

- [x] Carry the sign-in policy on the provider configuration the resolver reads, and return it with the client.
- [x] Pass it from the callback into provisioning instead of reading the configuration a second time.
- [x] Remove the provisioner's policy-reading seam, so the second read cannot come back.
- [x] Hold the window open in a test: a configuration saved during the exchange must not change the sign-in in flight.
