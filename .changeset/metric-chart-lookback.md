---
'@hyperdx/common-utils': patch
---

fix: Number, pie, table and bar-list charts on cumulative counter and histogram metrics now read back one auto-granularity interval (at least 5 minutes) before the range, so the first sample of each series counts when the series reported within that interval. Sum charts of either temporality without a time axis also no longer drop the samples before the first whole time bucket when the range starts between two bucket boundaries, so a delta counter tile on such a range reads higher too. Values read slightly higher than before; a time chart over the same range can still differ because the app widens its range to whole buckets. Gauges and counters read without an aggregation return the same values; delta series are otherwise unchanged. A builder chart converted to raw SQL skips the lookback.
