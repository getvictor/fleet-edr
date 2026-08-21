# Tasks

- [x] Break equal-stamp ties by `pidversion DESC` in the store's `GetParentPath`, sorted after the image ordering so issue #723 is preserved.
- [x] Rank a row carrying a pidversion above one that carries none, explicitly rather than relying on NULL collation.
- [x] Mirror both in the batch overlay's comparator, so the answer does not depend on whether parent and child shared a batch.
- [x] Cover the collision that actually occurs (two fork-only rows sharing a stamp) with the rows ingested in the opposite order to the kernel generation, so the old id tie-break would fail it.
- [x] Cover the mixed present/absent case.
- [x] Keep the existing equal-stamp assertion and record why it cannot be inverted.
