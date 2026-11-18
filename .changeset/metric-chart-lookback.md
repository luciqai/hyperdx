---
'@hyperdx/common-utils': patch
---

fix: Number, pie, table and bar-list charts on cumulative counter and histogram metrics now read back one auto-granularity interval (at least 5 minutes) before the range, so the first sample of each series counts. Counter charts of this kind also no longer drop the samples before the first whole time bucket when the range starts between two bucket boundaries. Their values read slightly higher than before; a time chart over the same range can still differ because the app widens its range to whole buckets. Gauges and delta-temporality metrics are unchanged.
