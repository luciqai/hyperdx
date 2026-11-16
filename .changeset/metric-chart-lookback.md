---
'@hyperdx/common-utils': patch
---

fix: Number, pie, table and bar-list charts on cumulative counter and histogram metrics now read back one auto-granularity interval (at least 5 minutes) before the range, so the first sample of each series counts and these charts agree with a time chart over a bucket-aligned range. Their values read slightly higher than before; gauges and delta-temporality metrics are unchanged.
