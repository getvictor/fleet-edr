# Tasks

- [x] Read the chain directly: the named process, its ancestors, and its descendants.
- [x] Bound descendants by each process's own lifetime, so a recycled number's children are not attributed to the earlier holder.
- [x] Cap the descendant walk and report only that as truncation.
- [x] Skip the host-window count, which a chain read has nothing to say about.
- [x] Ask for the chain from the page while it is focused on one, and for the window when it is not.
